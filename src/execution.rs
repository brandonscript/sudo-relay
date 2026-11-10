use crate::{
    broker::protected_path,
    protocol::{Command as RequestedCommand, Envelope, Spec},
};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 1024 * 1024;
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub cleanup_error: Option<String>,
    pub error: Option<String>,
}
impl Outcome {
    pub fn error(error: impl ToString) -> Self {
        Self {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            timed_out: false,
            cleanup_error: None,
            error: Some(error.to_string()),
        }
    }
}
fn executable(spec: &Spec) -> &str {
    match &spec.command {
        RequestedCommand::Argv { argv } => &argv[0],
        RequestedCommand::Script { interpreter, .. } => interpreter,
    }
}
pub fn validate_executable(spec: &Spec, development: bool) -> Result<()> {
    spec.validate()?;
    let path = Path::new(executable(spec));
    let resolved = if development {
        fs::canonicalize(path)?
    } else {
        protected_path(path, 0)?
    };
    let meta = fs::metadata(&resolved)?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        "executable must be an executable regular file"
    );
    Ok(())
}
fn drain(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut truncated = false;
    let mut chunk = [0; 8192];
    while let Ok(n) = reader.read(&mut chunk) {
        if n == 0 {
            break;
        }
        let keep = n.min(limit.saturating_sub(output.len()));
        output.extend_from_slice(&chunk[..keep]);
        truncated |= limit > 0 && keep != n;
    }
    (output, truncated)
}
fn kill_group(pid: u32) -> Option<String> {
    if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Some(error.to_string());
        }
    }
    None
}
pub fn execute(env: &Envelope, state_dir: &Path, development: bool, share_output: bool) -> Outcome {
    match run(env, state_dir, development, share_output) {
        Ok(outcome) => outcome,
        Err(e) => Outcome::error(format!("{e:#}")),
    }
}
fn run(env: &Envelope, state_dir: &Path, development: bool, share_output: bool) -> Result<Outcome> {
    validate_executable(&env.spec, development)?;
    let resolved = fs::canonicalize(executable(&env.spec))?;
    let mut command = Command::new(resolved);
    let script_path = state_dir.join(format!("{}.script", env.id));
    let script = match &env.spec.command {
        RequestedCommand::Argv { argv } => {
            command.args(&argv[1..]);
            false
        }
        RequestedCommand::Script { script, .. } => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&script_path)?;
            file.write_all(script.as_bytes())?;
            file.sync_all()?;
            command.arg(&script_path);
            true
        }
    };
    command
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", "/var/empty")
        .envs(&env.spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let spawned = command.spawn().context("could not launch approved command");
    // Interpreter opens the path after spawn, so removal must wait until the child exits.
    let result = (|| -> Result<Outcome> {
        let mut child = spawned?;
        let pid = child.id();
        let stdout = child.stdout.take().context("missing stdout pipe")?;
        let stderr = child.stderr.take().context("missing stderr pipe")?;
        let limit = if share_output { OUTPUT_LIMIT } else { 0 };
        let out = thread::spawn(move || drain(stdout, limit));
        let err = thread::spawn(move || drain(stderr, limit));
        let deadline = Instant::now() + Duration::from_secs(env.spec.timeout_secs);
        let mut timed_out = false;
        let mut cleanup_error = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    timed_out = true;
                    cleanup_error = kill_group(pid);
                    if cleanup_error.is_none() {
                        let _ = child.wait();
                    }
                    break None;
                }
                Err(e) => {
                    let cleanup = kill_group(pid);
                    anyhow::bail!("wait failed: {e}; cleanup: {cleanup:?}");
                }
            }
        };
        // A background descendant can retain pipes after its parent exits. Bound capture too.
        while (!out.is_finished() || !err.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !out.is_finished() || !err.is_finished() {
            timed_out = true;
            cleanup_error = cleanup_error.or_else(|| kill_group(pid));
            let capture_deadline = Instant::now() + Duration::from_millis(250);
            while (!out.is_finished() || !err.is_finished()) && Instant::now() < capture_deadline {
                thread::sleep(Duration::from_millis(10));
            }
        }
        let out_result = if out.is_finished() {
            out.join().unwrap_or_default()
        } else {
            cleanup_error.get_or_insert(
                "stdout capture remained open; descendant may have escaped process group".into(),
            );
            (Vec::new(), true)
        };
        let err_result = if err.is_finished() {
            err.join().unwrap_or_default()
        } else {
            cleanup_error.get_or_insert(
                "stderr capture remained open; descendant may have escaped process group".into(),
            );
            (Vec::new(), true)
        };
        Ok(Outcome {
            exit_code: status.and_then(|s| s.code()),
            stdout: String::from_utf8_lossy(&out_result.0).into(),
            stderr: String::from_utf8_lossy(&err_result.0).into(),
            truncated: out_result.1 || err_result.1,
            timed_out,
            cleanup_error,
            error: None,
        })
    })();
    if script {
        fs::remove_file(script_path).context("could not remove script snapshot")?;
    }
    result
}
