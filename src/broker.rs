use crate::execution::{self, Outcome};
use crate::protocol::{Envelope, Reply, Request};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub machine_id: String,
    pub agent_uid: u32,
    pub approver_uid: u32,
    pub socket_gid: u32,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    #[serde(default = "default_approval_ttl_secs")]
    pub approval_ttl_secs: u64,
}
pub fn default_approval_ttl_secs() -> u64 {
    300
}

impl Config {
    pub fn validate(&self, development: bool) -> Result<()> {
        ensure!(
            (1..=86_400).contains(&self.approval_ttl_secs),
            "approval_ttl_secs must be 1..86400 seconds"
        );
        ensure!(
            uuid::Uuid::parse_str(&self.machine_id).is_ok(),
            "machine_id must be a UUID"
        );
        ensure!(
            self.state_dir.is_absolute() && self.socket.is_absolute(),
            "paths must be absolute"
        );
        ensure!(
            self.socket.parent() != Some(self.state_dir.as_path()),
            "socket must not expose private state directory"
        );
        ensure!(
            development || (self.agent_uid != 0 && self.approver_uid != 0),
            "client identities must be unprivileged"
        );
        ensure!(
            development || self.agent_uid != self.approver_uid,
            "agent and approver must use separate identities"
        );
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Check the resolved path and every ancestor, so an unprivileged writer cannot replace trusted files.
pub fn protected_path(path: &Path, owner: u32) -> Result<PathBuf> {
    let resolved =
        fs::canonicalize(path).with_context(|| format!("cannot resolve {}", path.display()))?;
    ensure!(path.is_absolute(), "trusted path must be absolute");
    for component in path.ancestors().chain(resolved.ancestors()) {
        let meta = fs::metadata(component)?;
        ensure!(
            meta.uid() == owner && meta.mode() & 0o022 == 0,
            "{} must be owned by uid {owner} and not group/world writable",
            component.display()
        );
        #[cfg(target_os = "macos")]
        reject_extended_acl(component)?;
    }
    Ok(resolved)
}

#[cfg(target_os = "macos")]
fn reject_extended_acl(path: &Path) -> Result<()> {
    use std::ptr;
    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_valid(acl: *mut libc::c_void) -> libc::c_int;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            index: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    // Darwin sys/acl.h: ACL_TYPE_EXTENDED = 0x100, ACL_FIRST_ENTRY = 0.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    // Darwin reports an absent ACL as ENOENT; an open descriptor rules out a missing path.
    if acl.is_null() && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        return Ok(());
    }
    ensure!(
        !acl.is_null(),
        "cannot inspect ACL for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    let valid = unsafe { acl_valid(acl) };
    let mut entry = ptr::null_mut();
    let result = if valid == 0 {
        unsafe { acl_get_entry(acl, 0, &mut entry) }
    } else {
        0
    };
    let error = std::io::Error::last_os_error();
    unsafe { acl_free(acl) };
    // Reject even restrictive entries until effective ACL evaluation is implemented and reviewed.
    ensure!(
        valid == 0 && result == -1 && error.raw_os_error() == Some(libc::EINVAL),
        "{} must have no extended ACL entries",
        path.display()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Pending,
    Consumed,
    Running,
    Complete,
    Cancelled,
    Expired,
    Uncertain,
}
impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Uncertain => "uncertain",
        }
    }
}

pub struct Job {
    pub envelope: Envelope,
    pub share_output: bool,
}
struct StateLock(fs::File);
impl Drop for StateLock {
    fn drop(&mut self) {
        // A concurrent fork can briefly inherit the descriptor before exec closes it.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub struct Broker {
    pub config: Config,
    db: Connection,
    _lock: StateLock,
    owner: u32,
    development: bool,
    results: HashMap<String, Outcome>,
}
impl Broker {
    pub fn open(config: Config, development: bool) -> Result<Self> {
        config.validate(development)?;
        let owner = if development {
            unsafe { libc::geteuid() }
        } else {
            0
        };
        ensure!(
            development == (unsafe { libc::geteuid() } != 0),
            "development requires non-root; production requires root"
        );
        if !development {
            protected_path(&config.state_dir, owner)?;
        }
        let metadata = fs::symlink_metadata(&config.state_dir)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner
                && metadata.mode() & 0o077 == 0,
            "state directory must be private and owned by broker"
        );
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(config.state_dir.join("broker.lock"))?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "broker already owns state directory"
        );
        let path = config.state_dir.join("state.sqlite3");
        if !path.exists() {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
        }
        if path.exists() {
            Self::check_private_file(&path, owner)?;
        }
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, envelope TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, key_id TEXT);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, time INTEGER NOT NULL, id TEXT NOT NULL, event TEXT NOT NULL, key_id TEXT);
            BEGIN IMMEDIATE;
            INSERT INTO audit(time,id,event) SELECT unixepoch(),id,'uncertain' FROM requests WHERE state IN ('consumed','running');
            UPDATE requests SET state='uncertain' WHERE state IN ('consumed','running');
            INSERT INTO audit(time,id,event) SELECT unixepoch(),id,'cancelled_on_restart' FROM requests WHERE state='pending';
            UPDATE requests SET state='cancelled' WHERE state='pending'; COMMIT;")?;
        let has_output_policy: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('requests') WHERE name='share_output')",
            [],
            |row| row.get(0),
        )?;
        if !has_output_policy {
            db.execute_batch("ALTER TABLE requests ADD COLUMN share_output INTEGER NOT NULL DEFAULT 0 CHECK(share_output IN (0,1));")?;
        }
        Ok(Self {
            config,
            db,
            _lock: StateLock(lock),
            owner,
            development,
            results: HashMap::new(),
        })
    }
    fn check_private_file(path: &Path, owner: u32) -> Result<()> {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && m.uid() == owner && m.mode() & 0o077 == 0 && m.nlink() == 1,
            "{} must be a private regular file",
            path.display()
        );
        #[cfg(target_os = "macos")]
        reject_extended_acl(path)?;
        Ok(())
    }
    fn transition(
        &mut self,
        id: &str,
        state: State,
        key: Option<&str>,
        share_output: Option<bool>,
    ) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE requests SET state=?2,key_id=COALESCE(?3,key_id),share_output=COALESCE(?4,share_output) WHERE id=?1",
            params![id, state.as_str(), key, share_output],
        )?;
        tx.execute(
            "INSERT INTO audit(time,id,event,key_id) VALUES(?1,?2,?3,?4)",
            params![i64::try_from(now())?, id, state.as_str(), key],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn expire(&mut self, time: u64) -> Result<()> {
        let pending: Vec<(String, String)> = self
            .db
            .prepare("SELECT id,envelope FROM requests WHERE state='pending'")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, json) in pending {
            let env: Envelope = serde_json::from_str(&json)?;
            if time >= env.expires_at {
                self.transition(&id, State::Expired, None, None)?;
            }
        }
        Ok(())
    }
    fn load(&self, id: &str) -> Result<(Envelope, State, u32)> {
        let (json, state, attempts): (String, String, u32) = self
            .db
            .query_row(
                "SELECT envelope,state,attempts FROM requests WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .context("unknown request")?;
        Ok((
            serde_json::from_str(&json)?,
            serde_json::from_value(serde_json::Value::String(state))?,
            attempts,
        ))
    }
    fn key(&self, id: &str) -> Result<VerifyingKey> {
        ensure!(
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "invalid key id"
        );
        let path = self.config.state_dir.join("keys").join(format!("{id}.pub"));
        Self::check_private_file(&path, self.owner)?;
        if !self.development {
            protected_path(&path, self.owner)?;
        }
        let bytes: [u8; 32] = hex::decode(fs::read_to_string(path)?.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
        Ok(VerifyingKey::from_bytes(&bytes)?)
    }
    pub fn handle(&mut self, req: Request, uid: u32, time: u64) -> Result<(Reply, Option<Job>)> {
        ensure!(
            uid == self.config.agent_uid || uid == self.config.approver_uid,
            "peer not authorized"
        );
        self.expire(time)?;
        match req {
            Request::RequestExecution { mut spec } => {
                let total: u32 = self
                    .db
                    .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))?;
                ensure!(total < 10_000, "audit capacity reached; administrator must archive and rotate the broker state");
                spec.validate()?;
                execution::validate_executable(&spec, self.development)?;
                if let crate::protocol::Command::Argv { argv } = &mut spec.command {
                    argv[0] = fs::canonicalize(&argv[0])?
                        .to_str()
                        .context("executable path must be UTF-8")?
                        .into();
                }
                let count: u32 = self.db.query_row(
                    "SELECT COUNT(*) FROM requests WHERE state IN ('pending','consumed','running')",
                    [],
                    |r| r.get(0),
                )?;
                ensure!(count == 0, "another request is pending or running");
                let envelope = Envelope::new(
                    &self.config.machine_id,
                    spec,
                    time,
                    self.config.approval_ttl_secs,
                )?;
                let tx = self.db.transaction()?;
                tx.execute(
                    "INSERT INTO requests(id,envelope,state) VALUES(?1,?2,'pending')",
                    params![envelope.id, serde_json::to_string(&envelope)?],
                )?;
                tx.execute(
                    "INSERT INTO audit(time,id,event) VALUES(?1,?2,'pending')",
                    params![i64::try_from(time)?, envelope.id],
                )?;
                tx.commit()?;
                Ok((Reply::success(envelope.view()?), None))
            }
            Request::ExecutionStatus { id } => {
                let (env, state, _) = self.load(&id)?;
                Ok((
                    Reply::success(
                        serde_json::json!({"id":id,"state":state,"pending": if state == State::Pending {Some(env.view()?)} else {None},"output_shared":self.output_shared(&id)?,"outcome":self.results.get(&id)}),
                    ),
                    None,
                ))
            }
            Request::CancelExecution { id } => {
                let (_, state, _) = self.load(&id)?;
                ensure!(
                    state == State::Pending,
                    "only pending requests can be cancelled"
                );
                self.transition(&id, State::Cancelled, None, None)?;
                Ok((
                    Reply::success(serde_json::json!({"id":id,"state":"cancelled"})),
                    None,
                ))
            }
            Request::Approve {
                id,
                key_id,
                number,
                signature,
                share_output,
            } => {
                ensure!(uid == self.config.approver_uid, "peer cannot approve");
                let (env, state, attempts) = self.load(&id)?;
                ensure!(
                    state == State::Pending && time < env.expires_at,
                    "request is not pending"
                );
                let key = self.key(&key_id)?;
                let signature = Signature::from_slice(&hex::decode(signature)?)?;
                ensure!(env.version == 2, "unsupported approval version");
                key.verify_strict(&env.approval_payload(share_output)?, &signature)
                    .context("invalid approval signature")?;
                if number != env.number {
                    self.db
                        .execute("UPDATE requests SET attempts=attempts+1 WHERE id=?1", [&id])?;
                    if attempts >= 2 {
                        self.transition(&id, State::Cancelled, Some(&key_id), None)?;
                    }
                    anyhow::bail!("incorrect confirmation number");
                }
                // Consumption commits before any execution thread is created. Retries never launch twice.
                self.transition(&id, State::Consumed, Some(&key_id), Some(share_output))?;
                Ok((
                    Reply::success(serde_json::json!({"id":id,"state":"consumed"})),
                    Some(Job {
                        envelope: env,
                        share_output,
                    }),
                ))
            }
        }
    }
    pub fn running(&mut self, id: &str) -> Result<()> {
        self.transition(id, State::Running, None, None)
    }
    fn output_shared(&self, id: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT share_output FROM requests WHERE id=?1",
            [id],
            |row| row.get(0),
        )?)
    }
    pub fn finish(&mut self, id: &str, mut outcome: Outcome) -> Result<()> {
        self.transition(id, State::Complete, None, None)?;
        if !self.output_shared(id)? {
            outcome.stdout.clear();
            outcome.stderr.clear();
            outcome.truncated = false;
            outcome.error = outcome
                .error
                .map(|_| "Execution failed; details withheld".into());
            outcome.cleanup_error = outcome
                .cleanup_error
                .map(|_| "Process cleanup failed; details withheld".into());
        }
        // Output is deliberately memory-only and bounded independently of persistent audit history.
        if self.results.len() >= 32 {
            self.results.clear();
        }
        self.results.insert(id.into(), outcome);
        Ok(())
    }
    pub fn development(&self) -> bool {
        self.development
    }
}

#[cfg(all(test, target_os = "macos"))]
mod acl_tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, process::Command};

    #[test]
    fn private_file_rejects_acl_access_not_visible_in_mode_bits() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fixture-key");
        fs::write(&file, "public test data").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = unsafe { libc::geteuid() };
        Broker::check_private_file(&file, owner).unwrap();
        assert!(Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write"])
            .arg(&file)
            .status()
            .unwrap()
            .success());
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        let result = Broker::check_private_file(&file, owner);
        assert!(Command::new("/bin/chmod")
            .arg("-N")
            .arg(&file)
            .status()
            .unwrap()
            .success());
        assert!(result.unwrap_err().to_string().contains("extended ACL"));
        Broker::check_private_file(&file, owner).unwrap();
        assert!(reject_extended_acl(&dir.path().join("missing")).is_err());
    }
}
