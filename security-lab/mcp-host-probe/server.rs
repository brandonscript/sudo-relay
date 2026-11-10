//! Receipt-only transport probe. Deliberately has no broker, signer or command runner.
use rand::{rngs::OsRng, Rng, RngCore};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const URI: &str = "ui://sudo-relay-host-probe/inline-v4.html";
const COMMAND: &str = "/usr/bin/printf 'Receipt only; nothing executes\\n'";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}
fn random_hex<const N: usize>() -> String {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    capability: String,
    number: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
struct Request {
    id: String,
    expires_at: u64,
    digest: String,
    number: String,
    canary: String,
    capability: String,
    state: &'static str,
    attempts: u8,
}
impl Request {
    fn new(at: u64) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let expires_at = at + 300;
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&json!({
                "id": id, "expires_at": expires_at, "command": COMMAND,
                "mode": "receipt-only", "share_output": false
            }))
            .expect("fixed JSON"),
        ));
        Self {
            id,
            expires_at,
            digest,
            number: format!("{:02}", OsRng.gen_range(0..100)),
            canary: random_hex::<16>(),
            capability: random_hex::<32>(),
            state: "pending",
            attempts: 0,
        }
    }
    fn expire(&mut self, at: u64) {
        if self.state == "pending" && at >= self.expires_at {
            self.state = "expired";
        }
    }
    fn public(&self) -> Value {
        json!({"id":self.id,"expires_at":self.expires_at,"digest":self.digest,
            "command":COMMAND,"state":self.state,"share_output":false})
    }
    fn approve(&mut self, input: &Decision, at: u64) -> Result<(), &'static str> {
        self.expire(at);
        if input.id != self.id || self.state != "pending" {
            return Err("Request is not pending");
        }
        // shortcut: possession is not human presence; require authenticated host proof before production use.
        if input.capability != self.capability {
            return Err("Missing or invalid UI capability");
        }
        if input.number != self.number {
            self.attempts += 1;
            if self.attempts >= 3 {
                self.state = "denied";
            }
            return Err("Incorrect number");
        }
        self.state = "approved";
        Ok(())
    }
}
struct Ledger {
    instance: String,
    requests: Vec<Request>,
}
impl Ledger {
    fn new() -> Self {
        Self {
            instance: uuid::Uuid::new_v4().to_string(),
            requests: Vec::new(),
        }
    }
    fn result(&self, request: &Request) -> CallToolResult {
        let mut result = CallToolResult::success(vec![Content::text(
            "Receipt-only experiment. Nothing executes. This is not proof of human approval.",
        )]);
        result.structured_content = Some(
            json!({"variant":"inline-only-v1","instance":self.instance,"request":request.public(),
            "receipt_count":self.requests.iter().filter(|r| r.state == "approved").count()}),
        );
        result
    }
}
#[derive(Clone)]
struct Server {
    html: Arc<String>,
    ledger: Arc<Mutex<Ledger>>,
    tool_router: ToolRouter<Self>,
}
fn ui_meta() -> Meta {
    let mut meta = Meta::new();
    meta.insert("ui".into(), json!({"resourceUri":URI}));
    meta
}
fn app_only() -> Meta {
    let mut meta = Meta::new();
    meta.insert("ui".into(), json!({"visibility":["app"]}));
    meta
}
fn error(message: &str) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message)])
}
#[tool_router]
impl Server {
    fn new(html: String) -> Self {
        Self {
            html: Arc::new(html),
            ledger: Arc::new(Mutex::new(Ledger::new())),
            tool_router: Self::tool_router(),
        }
    }
    #[tool(description="Create a harmless fixed receipt-only test card. No command executes; no real credentials are used.",meta=ui_meta())]
    async fn new_probe(&self) -> Result<CallToolResult, McpError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| McpError::internal_error("ledger unavailable", None))?;
        for request in &mut ledger.requests {
            request.expire(now());
        }
        if ledger.requests.iter().any(|r| r.state == "pending") {
            return Ok(error("Cancel the pending probe first"));
        }
        if ledger.requests.len() >= 100 {
            return Ok(error("Probe limit reached; restart for a new instance"));
        }
        ledger.requests.push(Request::new(now()));
        let request = ledger.requests.last().expect("just inserted");
        let mut result = ledger.result(request);
        let mut meta = Meta::new();
        meta.insert(
            "probe".into(),
            json!({"id":request.id,"number":request.number,
            "canary":request.canary,"capability":request.capability}),
        );
        result.meta = Some(meta);
        Ok(result)
    }
    #[tool(
        description = "Read the receipt-only ledger. Does not reveal UI metadata.",
        annotations(read_only_hint = true)
    )]
    async fn probe_status(
        &self,
        Parameters(input): Parameters<Id>,
    ) -> Result<CallToolResult, McpError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| McpError::internal_error("ledger unavailable", None))?;
        let Some(request) = ledger.requests.iter_mut().find(|r| r.id == input.id) else {
            return Ok(error("Unknown request in this server instance"));
        };
        request.expire(now());
        let request = ledger
            .requests
            .iter()
            .find(|r| r.id == input.id)
            .expect("found above");
        Ok(ledger.result(request))
    }
    #[tool(description="Record a fake receipt using the card capability. App-only transport experiment, not human authentication.",meta=app_only())]
    async fn record_probe_approval(
        &self,
        Parameters(input): Parameters<Decision>,
    ) -> Result<CallToolResult, McpError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| McpError::internal_error("ledger unavailable", None))?;
        let Some(request) = ledger.requests.iter_mut().find(|r| r.id == input.id) else {
            return Ok(error("Unknown request in this server instance"));
        };
        if let Err(message) = request.approve(&input, now()) {
            return Ok(error(message));
        }
        let request = ledger
            .requests
            .iter()
            .find(|r| r.id == input.id)
            .expect("found above");
        Ok(ledger.result(request))
    }
    #[tool(description = "Deny a pending fake request. Never approves or executes anything.")]
    async fn cancel_probe(
        &self,
        Parameters(input): Parameters<Id>,
    ) -> Result<CallToolResult, McpError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| McpError::internal_error("ledger unavailable", None))?;
        let Some(request) = ledger.requests.iter_mut().find(|r| r.id == input.id) else {
            return Ok(error("Unknown request in this server instance"));
        };
        request.expire(now());
        if request.state != "pending" {
            return Ok(error("Request is not pending"));
        }
        request.state = "denied";
        let request = ledger
            .requests
            .iter()
            .find(|r| r.id == input.id)
            .expect("found above");
        Ok(ledger.result(request))
    }
}
#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerInfo {
        ServerInfo { instructions:Some("Local receipt-only MCP Apps transport experiment. No commands execute. Never request real credentials. UI-only metadata and app-only tools are being tested, not assumed secure.".into()),
            capabilities:ServerCapabilities::builder().enable_tools().enable_resources().build(),
            server_info:Implementation {name:"sudo-relay-host-probe".into(),version:"0.1.6".into(),..Default::default()},..Default::default() }
    }
    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            meta: None,
            next_cursor: None,
            resources: vec![RawResource {
                uri: URI.into(),
                name: "receipt-probe".into(),
                title: Some("Receipt-only approval experiment".into()),
                description: None,
                mime_type: Some("text/html;profile=mcp-app".into()),
                size: None,
                icons: None,
                meta: None,
            }
            .no_annotation()],
        })
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri != URI {
            return Err(McpError::resource_not_found("unknown resource", None));
        }
        Ok(ReadResourceResult {
            contents: vec![ResourceContents::TextResourceContents {
                uri: URI.into(),
                mime_type: Some("text/html;profile=mcp-app".into()),
                text: self.html.as_str().into(),
                meta: Some({
                    let mut m = Meta::new();
                    m.insert(
                        "ui".into(),
                        json!({"csp":{"connectDomains":[],"resourceDomains":[]}}),
                    );
                    m.insert(
                        "openai/ui".into(),
                        json!({"availableDisplayModes":["inline"],"preferredDisplayMode":"inline"}),
                    );
                    m
                }),
            }],
        })
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } != 0,
        "Run this probe as an ordinary user"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 1, "Usage: mcp-host-probe CARD_HTML");
    let html = std::fs::read_to_string(&args[0])?;
    Server::new(html)
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn decision(r: &Request) -> Decision {
        Decision {
            id: r.id.clone(),
            capability: r.capability.clone(),
            number: r.number.clone(),
        }
    }
    #[test]
    fn possession_can_approve_but_replay_cannot() {
        let mut r = Request::new(100);
        let input = decision(&r);
        assert!(r.approve(&input, 101).is_ok());
        assert!(r.approve(&input, 102).is_err());
        assert_eq!(r.state, "approved");
    }
    #[test]
    fn wrong_capability_id_expiry_denial_and_three_wrong_numbers_reject() {
        let mut r = Request::new(100);
        let mut input = decision(&r);
        input.capability.clear();
        assert!(r.approve(&input, 101).is_err());
        assert_eq!(r.attempts, 0);
        input = decision(&r);
        input.id.push('x');
        assert!(r.approve(&input, 101).is_err());
        input = decision(&r);
        assert!(r.approve(&input, 400).is_err());
        assert_eq!(r.state, "expired");
        r = Request::new(100);
        input = decision(&r);
        input.number = "wrong".into();
        for _ in 0..3 {
            assert!(r.approve(&input, 101).is_err());
        }
        assert_eq!(r.state, "denied");
        assert!(r.approve(&decision(&r), 101).is_err());
    }
    #[test]
    fn capability_cannot_approve_another_request() {
        let first = Request::new(100);
        let mut second = Request::new(100);
        let mut input = decision(&first);
        input.id = second.id.clone();
        input.number = second.number.clone();
        assert!(second.approve(&input, 101).is_err());
        assert_eq!(second.state, "pending");
    }
    #[test]
    fn public_view_excludes_ui_secrets_and_input_rejects_extra_fields() {
        let r = Request::new(100);
        let result = Ledger::new().result(&r);
        let public = serde_json::to_string(&result).unwrap();
        assert!(!public.contains(&r.canary));
        assert!(!public.contains(&r.capability));
        assert!(!public.contains("\"number\""));
        assert!(result.meta.is_none());
        assert!(serde_json::from_value::<Decision>(
            json!({"id":"x","capability":"x","number":"00","human":true})
        )
        .is_err());
    }
    #[tokio::test]
    async fn concurrent_replays_create_one_receipt() {
        let server = Server::new(String::new());
        let result = server.new_probe().await.unwrap();
        let hidden = &result.meta.unwrap()["probe"];
        let input = || {
            Parameters(Decision {
                id: hidden["id"].as_str().unwrap().into(),
                capability: hidden["capability"].as_str().unwrap().into(),
                number: hidden["number"].as_str().unwrap().into(),
            })
        };
        let (a, b) = tokio::join!(
            server.record_probe_approval(input()),
            server.record_probe_approval(input())
        );
        assert_ne!(a.unwrap().is_error, b.unwrap().is_error);
        assert_eq!(
            server
                .ledger
                .lock()
                .unwrap()
                .requests
                .iter()
                .filter(|r| r.state == "approved")
                .count(),
            1
        );
    }
}
