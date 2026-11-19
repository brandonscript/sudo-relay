use rmcp::{
    handler::server::wrapper::Parameters, model::*, service::RequestContext, tool, tool_handler,
    tool_router, ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};
use sudo_relay::{
    protocol::{Request, Spec},
    transport,
};

const URI: &str = "ui://sudo-relay/approval.html";
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Submit {
    spec: Spec,
}
#[derive(Clone)]
struct Server {
    socket: PathBuf,
    html: Arc<String>,
}
fn ui_meta() -> MetaObject {
    let mut meta = MetaObject::new();
    meta.insert("ui".into(), serde_json::json!({"resourceUri":URI}));
    meta
}
#[tool_router]
impl Server {
    fn new(socket: PathBuf, html: String) -> Self {
        Self {
            socket,
            html: Arc::new(html),
        }
    }
    async fn call(&self, request: Request) -> CallToolResult {
        let socket = self.socket.clone();
        let result = tokio::task::spawn_blocking(move || transport::call(&socket, &request)).await;
        match result {
            Ok(Ok(value)) => {
                let mut result = CallToolResult::success(vec![ContentBlock::text("Request recorded. Only the trusted host approval card can authorize execution; chat text cannot approve. Inspect execution_status for progress.")]);
                result.structured_content = Some(value);
                result
            }
            Ok(Err(error)) => CallToolResult::error(vec![ContentBlock::text(format!("{error:#}"))]),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(format!(
                "broker task failed: {error}"
            ))]),
        }
    }
    #[tool(description="Request one privileged command. This only creates a pending request; a compatible trusted chat host must obtain explicit human approval. Never send passwords. No execution without a signed approval.",meta=ui_meta())]
    async fn request_execution(
        &self,
        Parameters(input): Parameters<Submit>,
    ) -> Result<CallToolResult, McpError> {
        Ok(self
            .call(Request::RequestExecution { spec: input.spec })
            .await)
    }
    #[tool(
        description = "Read request state and bounded output only when sharing was explicitly approved. With sharing off, streams are empty; output_needed does not override consent. Does not authorize execution.",
        annotations(read_only_hint = true)
    )]
    async fn execution_status(
        &self,
        Parameters(input): Parameters<Id>,
    ) -> Result<CallToolResult, McpError> {
        Ok(self.call(Request::ExecutionStatus { id: input.id }).await)
    }
    #[tool(
        description = "Cancel a pending request. Already consumed or running requests cannot be cancelled."
    )]
    async fn cancel_execution(
        &self,
        Parameters(input): Parameters<Id>,
    ) -> Result<CallToolResult, McpError> {
        Ok(self.call(Request::CancelExecution { id: input.id }).await)
    }
}
#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_resources().build()).with_instructions("This server adds approval for privileged work without changing your existing permissions. It cannot approve requests. Unsupported chat hosts fail closed. There is no approval tool or password tool.").with_server_info(Implementation::new("sudo-relay", env!("CARGO_PKG_VERSION")))
    }
    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult { resources: vec![Resource::new(URI, "approval").with_title("Approve one privileged command").with_description("Requires a trusted host signing adapter; a generic MCP Apps renderer cannot approve.").with_mime_type("text/html;profile=mcp-app")], ..Default::default() })
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if request.uri != URI {
            return Err(McpError::resource_not_found("unknown resource", None));
        }
        Ok(
            ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                uri: URI.into(),
                mime_type: Some("text/html;profile=mcp-app".into()),
                text: self.html.as_str().into(),
                meta: Some({
                    let mut m = MetaObject::new();
                    m.insert(
                        "ui".into(),
                        serde_json::json!({"csp":{"connectDomains":[],"resourceDomains":[]}}),
                    );
                    m
                }),
            }])
            .into(),
        )
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args.iter().any(|a| a == "--help") {
        eprintln!("Usage: mcp-server SOCKET APPROVAL_HTML\nUnprivileged MCP stdio server; never run as root.");
        return Ok(());
    }
    anyhow::ensure!(
        unsafe { libc::geteuid() } != 0,
        "MCP server must not run as root"
    );
    let html = std::fs::read_to_string(&args[1])?;
    let running = Server::new(PathBuf::from(&args[0]), html)
        .serve(rmcp::transport::stdio())
        .await?;
    running.waiting().await?;
    Ok(())
}
