//! Development-only stdio fixture. It deliberately has no executor call.
use anyhow::{ensure, Context, Result};
use std::io::{BufRead, Read, Write};
use sudo_relay::{
    broker::{now, Broker, Config},
    protocol::{Reply, Request, MAX_REQUEST_BYTES},
};

fn main() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    ensure!(uid != 0, "receipt fixture refuses root");
    ensure!(
        std::env::var("SUDO_RELAY_RECEIPT_LAB").as_deref() == Ok("1"),
        "explicit receipt lab opt-in required"
    );
    let path = std::env::args()
        .nth(1)
        .context("expected disposable config path")?;
    let mut config_bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut config_bytes)?;
    ensure!(config_bytes.len() <= MAX_REQUEST_BYTES, "config too large");
    let config: Config = serde_json::from_slice(&config_bytes)?;
    ensure!(
        config.agent_uid == uid && config.approver_uid == uid,
        "fixture identities must match current user"
    );
    let mut broker = Broker::open(config, true)?;
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(60));
        std::process::exit(2);
    });
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        if Read::by_ref(&mut input)
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?
            == 0
        {
            break;
        }
        ensure!(line.len() <= MAX_REQUEST_BYTES, "request too large");
        let result = serde_json::from_slice::<Request>(&line)
            .map_err(anyhow::Error::from)
            .and_then(|request| broker.handle(request, uid, now()));
        let (reply, consumed) = match result {
            Ok((reply, job)) => {
                let consumed = job.is_some();
                // Never forward a Job to running(), finish(), transport::serve() or an executor.
                drop(job);
                (reply, consumed)
            }
            Err(error) => (Reply::error(error.to_string()), false),
        };
        serde_json::to_writer(
            &mut output,
            &serde_json::json!({
                "receipt_only": true, "commands_executed": 0,
                "approval_consumed": consumed, "reply": reply,
            }),
        )?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
