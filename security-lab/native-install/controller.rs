//! Manually launched receipt fixture. Never dispatches the command executor.
use anyhow::{bail, ensure, Context, Result};
use std::{collections::BTreeMap, path::Path, time::Duration};
use sudo_relay::{
    broker::{read_protected_file, Broker, Config},
    protocol::{Command, Request, Spec},
    transport,
};

fn drop_identity(uid: u32, gid: u32) -> Result<()> {
    ensure!(uid != 0, "client must be unprivileged");
    // Only this fixture's socket group survives; never inherit administrator groups.
    ensure!(unsafe { libc::setgroups(1, &gid) } == 0, "setgroups failed");
    ensure!(unsafe { libc::setgid(gid) } == 0, "setgid failed");
    ensure!(unsafe { libc::setuid(uid) } == 0, "setuid failed");
    ensure!(
        unsafe {
            libc::getuid() == uid
                && libc::geteuid() == uid
                && libc::getgid() == gid
                && libc::getegid() == gid
        },
        "identity drop failed"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        unsafe { libc::getuid() == 0 && libc::geteuid() == 0 },
        "administrator launch required; never setuid-install this binary"
    );
    ensure!(
        (2..=3).contains(&args.len()),
        "expected OP CONFIG [PUBLIC_KEY_OR_REQUEST_ID]"
    );
    unsafe { libc::umask(0o077) };
    let config: Config = serde_json::from_slice(&read_protected_file(Path::new(&args[1]), 4096)?)?;
    config.validate(false)?;
    match args[0].as_str() {
        "stage-candidate" if args.len() == 3 => {
            // Provisional fixture only. This is not administrator-authenticated enrollment.
            ensure!(
                args[2].starts_with("p256-sha256:"),
                "P-256 candidate required"
            );
            Broker::pair_key(&config, false, "native", &args[2])?;
        }
        "serve" | "serve-lost-ack" if args.len() == 2 => {
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(360));
                std::process::exit(2);
            });
            if args[0] == "serve-lost-ack" {
                transport::serve_receipts_losing_ack(config, false)?;
            } else {
                transport::serve_receipts(config, false)?;
            }
        }
        "request" if args.len() == 2 => {
            let canary = config
                .socket
                .parent()
                .context("missing socket parent")?
                .join("must-not-exist");
            let spec = Spec {
                command: Command::Argv { argv: vec!["/usr/bin/touch".into(), canary.to_str().context("invalid canary path")?.into()] },
                reason: "Confirm this test key for temporary administrator pairing. This records a receipt only; the example command must never run.".into(),
                env: BTreeMap::new(), timeout_secs: 30, output_needed: false,
            };
            spec.validate()?;
            drop_identity(config.agent_uid, config.socket_gid)?;
            println!(
                "{}",
                transport::call_protected(&config.socket, &Request::RequestExecution { spec })?
            );
        }
        "status" if args.len() == 3 => {
            uuid::Uuid::parse_str(&args[2])?;
            drop_identity(config.approver_uid, config.socket_gid)?;
            println!(
                "{}",
                transport::call_protected(
                    &config.socket,
                    &Request::ExecutionStatus {
                        id: args[2].clone()
                    }
                )?
            );
        }
        _ => bail!("unsupported receipt-lab operation"),
    }
    Ok(())
}
