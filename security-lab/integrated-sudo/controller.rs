//! Disposable lab adapter: container by default; VM use requires explicit build and machine opt-in.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{BufRead, Read, Write},
    path::Path,
    process::{Command, Stdio},
};
use sudo_relay::{
    broker::{read_protected_file, Broker, Config},
    execution::Outcome,
    protocol::{Reply, Request, Spec},
    transport::{self, SudoLabExecutor},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    config: Config,
    sponsor: Value,
}
fn launcher(op: &str, input: &Value) -> Result<Value> {
    let mut child = Command::new("/usr/local/bin/python3")
        .args(["-I", "/integration/launcher.py", op])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("launcher stdin")?
        .write_all(&serde_json::to_vec(input)?)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "native sudo adapter rejected operation"
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
struct NativeSudo(Value);
impl SudoLabExecutor for NativeSudo {
    fn check(&self, spec: &Spec) -> Result<()> {
        launcher("check", &json!({"sponsor":self.0, "spec":spec}))?;
        Ok(())
    }
    fn execute(&self, job: sudo_relay::broker::Job) -> Outcome {
        let result = launcher(
            "launch",
            &json!({"sponsor":self.0, "envelope":job.envelope, "share_output":job.share_output}),
        )
        .and_then(|value| Ok(serde_json::from_value(value["outcome"].clone())?));
        result.unwrap_or_else(|error| Outcome::error(format!("{error:#}")))
    }
}
fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("review-channel") {
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "review channel must be unprivileged"
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Target {
            socket: std::path::PathBuf,
        }
        let target: Target = serde_json::from_slice(&read_protected_file(
            Path::new("/lab/ssh-target.json"),
            4096,
        )?)?;
        let mut bytes = Vec::new();
        std::io::stdin().take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "request too large");
        let request: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            matches!(
                request,
                Request::ExecutionStatus { .. }
                    | Request::Approve { .. }
                    | Request::CancelExecution { .. }
            ),
            "review channel cannot create requests or promote receipts"
        );
        let reply = match transport::call_protected(&target.socket, &request) {
            Ok(value) => Reply::success(value),
            Err(error) => Reply::error(format!("{error:#}")),
        };
        println!("{}", serde_json::to_string(&reply)?);
        return Ok(());
    }
    if std::env::args().nth(1).as_deref() == Some("decision-payload") {
        let mut bytes = Vec::new();
        std::io::stdin().take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "payload input too large");
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Decision {
            envelope: sudo_relay::protocol::Envelope,
            share_output: bool,
            receipt: bool,
        }
        let input: Decision = serde_json::from_slice(&bytes)?;
        let payload = if input.receipt {
            input
                .envelope
                .receipt_approval_payload(input.share_output)?
        } else {
            input.envelope.approval_payload(input.share_output)?
        };
        println!("{}", hex::encode(payload));
        return Ok(());
    }
    transport::ensure_sudo_lab_environment()?;
    ensure!(
        unsafe { libc::getuid() == 0 && libc::geteuid() == 0 },
        "root fixture controller required; never setuid install"
    );
    let path = std::env::args().nth(1).context("enrollment path")?;
    let enrollment: Enrollment =
        serde_json::from_slice(&read_protected_file(Path::new(&path), 8192)?)?;
    let config = enrollment.config;
    if std::env::args().nth(2).as_deref() == Some("pair") {
        let public = read_protected_file(Path::new("/lab/human-public.hex"), 1024)?;
        Broker::pair_key(&config, false, "human", std::str::from_utf8(&public)?)?;
        return Ok(());
    }
    if std::env::args().nth(2).as_deref() == Some("revoke") {
        return Broker::revoke_key(&config, false, "human");
    }
    if std::env::args().nth(2).as_deref() == Some("serve") {
        return transport::serve_sudo_lab(
            config,
            std::sync::Arc::new(NativeSudo(enrollment.sponsor)),
        );
    }
    let mut broker = Broker::open(config.clone(), false)?;
    for line in std::io::stdin().lock().lines() {
        let result = (|| -> Result<Value> {
            let line = line?;
            ensure!(line.len() <= 65536, "oversized fixture input");
            let request: Request = serde_json::from_str(&line)?;
            let uid = match &request {
                Request::RequestExecution { spec } => {
                    launcher("check", &json!({"sponsor":enrollment.sponsor, "spec":spec}))?;
                    config.agent_uid
                }
                Request::Approve { .. } | Request::CancelExecution { .. } => config.approver_uid,
                _ => config.agent_uid,
            };
            let (reply, job) = broker.handle_current(request, uid)?;
            let mut value = reply.value()?;
            // Emit exact canonical decision bytes for the separate fixture signer, not a second serializer.
            if let Some(envelope) = value.get("envelope") {
                let env: sudo_relay::protocol::Envelope = serde_json::from_value(envelope.clone())?;
                value["approval_payload"] = json!(hex::encode(env.approval_payload(false)?));
                value["receipt_payload"] = json!(hex::encode(env.receipt_approval_payload(false)?));
            }
            if let Some(job) = job {
                // No recoverable queue: an interrupted launch stays consumed/uncertain, never retried.
                let outcome = launcher(
                    "launch",
                    &json!({"sponsor":enrollment.sponsor,
                    "envelope":job.envelope, "share_output":job.share_output}),
                );
                let result = outcome?;
                broker.finish(
                    &job.envelope.id,
                    Outcome {
                        exit_code: result["exit_code"].as_i64().map(|v| v as i32),
                        stdout: String::new(),
                        stderr: String::new(),
                        truncated: false,
                        timed_out: false,
                        cleanup_error: None,
                        error: None,
                    },
                )?;
                value["launch"] = result;
            }
            Ok(value)
        })();
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
            }
        );
        std::io::stdout().flush()?;
    }
    Ok(())
}
