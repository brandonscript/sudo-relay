use anyhow::{bail, ensure, Context, Result};
use ciborium::value::Value as Cbor;
use rand::{rngs::OsRng, Rng};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_SPEC_BYTES: usize = 16_384;
pub const DOMAIN: &str = "sudo-relay/request/v2";

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Argv { argv: Vec<String> },
    Script { interpreter: String, script: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub command: Command,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub output_needed: bool,
}
fn default_timeout() -> u64 {
    300
}

fn safe_text(s: &str) -> bool {
    !s.chars().any(|c| {
        c.is_control() || matches!(c as u32, 0x200b..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
    })
}
impl Spec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_SPEC_BYTES,
            "request exceeds 16 KiB review limit"
        );
        ensure!(
            (1..=300).contains(&self.timeout_secs),
            "timeout must be 1..300 seconds"
        );
        ensure!(
            safe_text(&self.reason),
            "reason contains control or direction characters"
        );
        match &self.command {
            Command::Argv { argv } => {
                ensure!(
                    !argv.is_empty() && argv.len() <= 256,
                    "expected 1..256 arguments"
                );
                ensure!(
                    std::path::Path::new(&argv[0]).is_absolute(),
                    "executable must be absolute"
                );
                ensure!(
                    argv.iter().all(|a| safe_text(a)),
                    "arguments contain control or direction characters"
                );
            }
            Command::Script {
                interpreter,
                script,
            } => {
                ensure!(
                    matches!(interpreter.as_str(), "/bin/sh" | "/bin/bash"),
                    "unsupported interpreter"
                );
                ensure!(!script.is_empty(), "script is empty");
                // Scripts need line breaks, but terminal escapes and bidi controls are never needed.
                ensure!(
                    safe_text(&script.replace(['\n', '\t'], "")),
                    "script contains control or direction characters"
                );
            }
        }
        for (key, value) in &self.env {
            let allowed = matches!(key.as_str(), "LANG" | "TZ" | "TERM" | "DEBIAN_FRONTEND")
                || (key.starts_with("LC_")
                    && key.bytes().all(|c| c.is_ascii_uppercase() || c == b'_'));
            ensure!(
                allowed && safe_text(value),
                "environment variable not allowed: {key}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub machine_id: String,
    pub id: String,
    pub nonce: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub number: String,
    pub spec: Spec,
}
impl Envelope {
    pub fn new(machine_id: &str, spec: Spec, now: u64, approval_ttl_secs: u64) -> Result<Self> {
        Ok(Self {
            version: 2,
            machine_id: machine_id.into(),
            id: Uuid::new_v4().to_string(),
            nonce: hex::encode(OsRng.gen::<[u8; 32]>()),
            created_at: now,
            expires_at: now
                .checked_add(approval_ttl_secs)
                .context("approval expiry overflow")?,
            number: OsRng.gen_range(10..=99).to_string(),
            spec,
        })
    }
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        fn text(s: &str) -> Cbor {
            Cbor::Text(s.into())
        }
        let command = match &self.spec.command {
            Command::Argv { argv } => Cbor::Array(vec![
                text("argv"),
                Cbor::Array(argv.iter().map(|s| text(s)).collect()),
            ]),
            Command::Script {
                interpreter,
                script,
            } => Cbor::Array(vec![text("script"), text(interpreter), text(script)]),
        };
        let env = Cbor::Array(
            self.spec
                .env
                .iter()
                .map(|(k, v)| Cbor::Array(vec![text(k), text(v)]))
                .collect(),
        );
        let payload = Cbor::Array(vec![
            text(DOMAIN),
            text(&self.machine_id),
            text(&self.id),
            text(&self.nonce),
            Cbor::Integer(self.created_at.into()),
            Cbor::Integer(self.expires_at.into()),
            text(&self.number),
            command,
            env,
            text(&self.spec.reason),
            Cbor::Integer(self.spec.timeout_secs.into()),
            Cbor::Bool(self.spec.output_needed),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes)?;
        Ok(bytes)
    }
    pub fn approval_payload(&self, share_output: bool) -> Result<Vec<u8>> {
        approval_payload(&self.signing_payload()?, share_output)
    }
    pub fn view(&self) -> Result<PendingView> {
        let bytes = self.signing_payload()?;
        Ok(PendingView {
            envelope: self.clone(),
            digest: hex::encode(Sha256::digest(&bytes)),
            signing_payload: hex::encode(bytes),
        })
    }
}
pub fn approval_payload(request_payload: &[u8], share_output: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Cbor::Array(vec![
            Cbor::Text("sudo-relay/decision/v2".into()),
            Cbor::Bytes(request_payload.to_vec()),
            Cbor::Bool(share_output),
        ]),
        &mut bytes,
    )?;
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingView {
    pub envelope: Envelope,
    pub signing_payload: String,
    pub digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    RequestExecution {
        spec: Spec,
    },
    ExecutionStatus {
        id: String,
    },
    CancelExecution {
        id: String,
    },
    Approve {
        id: String,
        key_id: String,
        number: String,
        signature: String,
        share_output: bool,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Reply {
    Ok { ok: bool, value: serde_json::Value },
    Error { ok: bool, error: String },
}
impl Reply {
    pub fn success(value: impl Serialize) -> Self {
        match serde_json::to_value(value) {
            Ok(value) => Self::Ok { ok: true, value },
            Err(e) => Self::error(e.to_string()),
        }
    }
    pub fn error(error: impl Into<String>) -> Self {
        Self::Error {
            ok: false,
            error: error.into(),
        }
    }
    pub fn value(self) -> Result<serde_json::Value> {
        match self {
            Self::Ok { ok: true, value } => Ok(value),
            Self::Error { error, .. } => bail!("{error}"),
            _ => bail!("invalid response"),
        }
    }
}
