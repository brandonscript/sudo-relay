//! Explicit fixed-command developer preview; installation is separate from lab fixtures.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
use sudo_relay::{
    broker::{read_protected_file, Broker, Config},
    execution::Outcome,
    protocol::Spec,
    transport::{self, SudoLabExecutor},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    config: Config,
    sponsor: Value,
}
struct Executor {
    enrollment: PathBuf,
    sponsor: Value,
}
impl Executor {
    fn call(&self, operation: &str, value: Value) -> Result<Value> {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "/usr/local/libexec/sudo-relay/launcher.py"])
            .arg(&self.enrollment)
            .arg(operation)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .context("adapter stdin")?
            .write_all(&serde_json::to_vec(&value)?)?;
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "sudo preview adapter rejected operation"
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}
impl SudoLabExecutor for Executor {
    fn check(&self, spec: &Spec) -> Result<()> {
        self.call("check", json!({"sponsor":self.sponsor,"spec":spec}))?;
        Ok(())
    }
    fn execute(&self, job: sudo_relay::broker::Job) -> Outcome {
        self.call(
            "launch",
            json!({"sponsor":self.sponsor,"envelope":job.envelope,"share_output":job.share_output}),
        )
        .and_then(|v| Ok(serde_json::from_value(v["outcome"].clone())?))
        .unwrap_or_else(|e| Outcome::error(format!("{e:#}")))
    }
}
fn main() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux") && unsafe { libc::getuid() == 0 && libc::geteuid() == 0 },
        "root Linux preview only"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() >= 2,
        "use serve|pair|revoke ENROLLMENT [PUBLIC_KEY]"
    );
    let path = PathBuf::from(&args[1]);
    let e: Enrollment = serde_json::from_slice(&read_protected_file(&path, 16384)?)?;
    let uid = e.sponsor["uid"].as_u64().context("sponsor UID")?;
    ensure!(uid > 0 && uid <= u32::MAX as u64, "invalid sponsor UID");
    ensure!(
        path == Path::new("/etc/sudo-relay")
            .join(uid.to_string())
            .join("enrollment.json"),
        "wrong enrollment path"
    );
    ensure!(
        e.config.state_dir
            == Path::new("/var/lib/sudo-relay")
                .join(uid.to_string())
                .join("broker"),
        "wrong state path"
    );
    e.config.validate(false)?;
    match args[0].as_str() {
        "serve" if args.len() == 2 => transport::serve_sudo_preview(
            e.config,
            Arc::new(Executor {
                enrollment: path,
                sponsor: e.sponsor,
            }),
        ),
        "pair" if args.len() == 3 => Broker::pair_key(&e.config, false, "human", &args[2]),
        "revoke" if args.len() == 2 => Broker::revoke_key(&e.config, false, "human"),
        _ => anyhow::bail!("invalid preview arguments"),
    }
}
