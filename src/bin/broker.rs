use anyhow::{bail, ensure, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use sudo_relay::{
    broker::{protected_path, Config},
    transport,
};

const HELP: &str = "sudo-relay broker (experimental)

broker [--development] init CONFIG STATE_DIR SOCKET AGENT_UID APPROVER_UID SOCKET_GID
broker [--development] serve CONFIG
broker [--development] pair CONFIG KEY_ID PUBLIC_KEY_HEX
broker [--development] revoke CONFIG KEY_ID

Production commands require root. --development requires non-root and never elevates.
init refuses existing configuration; serve never runs sudo or reads passwords.
";
fn load(path: &Path, development: bool) -> Result<Config> {
    if !development {
        protected_path(path, 0)?;
    }
    let config: Config = serde_json::from_slice(&fs::read(path)?)?;
    config.validate(development)?;
    Ok(config)
}
fn main() -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    let development = args.first().is_some_and(|a| a == "--development");
    if development {
        args.remove(0);
    }
    ensure!(
        development == (unsafe { libc::geteuid() } != 0),
        "use root for production, or --development as an ordinary user"
    );
    match args.first().map(String::as_str) {
        Some("init") if args.len() == 7 => {
            let config = Config {
                machine_id: uuid::Uuid::new_v4().to_string(),
                state_dir: PathBuf::from(&args[2]),
                socket: PathBuf::from(&args[3]),
                agent_uid: args[4].parse()?,
                approver_uid: args[5].parse()?,
                socket_gid: args[6].parse()?,
                approval_ttl_secs: 300,
                max_execution_secs: 300,
            };
            config.validate(development)?;
            for (dir, mode) in [
                (config.state_dir.as_path(), 0o700),
                (config.state_dir.join("keys").as_path(), 0o700),
            ] {
                fs::create_dir_all(dir)?;
                if !development {
                    protected_path(dir, 0)?;
                }
                fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
            }
            let socket_dir = config.socket.parent().context("missing socket parent")?;
            if !socket_dir.exists() {
                fs::create_dir_all(socket_dir)?;
                fs::set_permissions(socket_dir, fs::Permissions::from_mode(0o755))?;
            }
            if !development {
                protected_path(socket_dir, 0)?;
                protected_path(
                    Path::new(&args[1])
                        .parent()
                        .context("missing config parent")?,
                    0,
                )?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&args[1])?;
            file.write_all(&serde_json::to_vec_pretty(&config)?)?;
            file.sync_all()?;
            println!("Configuration created. Machine: {}", config.machine_id);
        }
        Some("serve") if args.len() == 2 => {
            transport::serve(load(Path::new(&args[1]), development)?, development)?
        }
        Some("pair") if args.len() == 4 => {
            let config = load(Path::new(&args[1]), development)?;
            validate_key_id(&args[2])?;
            let bytes: [u8; 32] = hex::decode(&args[3])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("expected a 32-byte public key"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
            let keys = config.state_dir.join("keys");
            if !development {
                protected_path(&keys, 0)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(keys.join(format!("{}.pub", args[2])))?;
            file.write_all(hex::encode(bytes).as_bytes())?;
            file.sync_all()?;
            fs::File::open(keys)?.sync_all()?;
            println!("Approver paired: {}", args[2]);
        }
        Some("revoke") if args.len() == 3 => {
            let config = load(Path::new(&args[1]), development)?;
            validate_key_id(&args[2])?;
            let keys = config.state_dir.join("keys");
            if !development {
                protected_path(&keys, 0)?;
            }
            fs::remove_file(keys.join(format!("{}.pub", args[2])))?;
            fs::File::open(keys)?.sync_all()?;
            println!("Approver revoked: {}", args[2]);
        }
        _ => bail!("invalid arguments; use --help"),
    }
    Ok(())
}
fn validate_key_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
        "key id must contain 1..64 letters, digits, hyphens or underscores"
    );
    Ok(())
}
