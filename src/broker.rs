use crate::approval_key::ApprovalKey;
use crate::execution::{self, Outcome};
use crate::protocol::{Envelope, Reply, Request, MAX_EXECUTION_TIMEOUT_SECS};
use anyhow::{ensure, Context, Result};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Read,
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
    #[serde(default = "default_max_execution_secs")]
    pub max_execution_secs: u64,
}
pub fn default_approval_ttl_secs() -> u64 {
    300
}

pub fn default_max_execution_secs() -> u64 {
    300
}

impl Config {
    pub fn validate(&self, development: bool) -> Result<()> {
        ensure!(
            (1..=86_400).contains(&self.approval_ttl_secs),
            "approval_ttl_secs must be 1..86400 seconds"
        );
        ensure!(
            (1..=MAX_EXECUTION_TIMEOUT_SECS).contains(&self.max_execution_secs),
            "max_execution_secs must be 1..86400 seconds"
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

/// Read a bounded regular file beneath root-controlled ancestors.
pub fn read_protected_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        (1..=crate::protocol::MAX_REQUEST_BYTES).contains(&max_bytes),
        "invalid protected file size limit"
    );
    let resolved = protected_path(path, 0)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(resolved)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "expected a root-owned regular file without group/world write access"
    );
    ensure!(meta.len() <= max_bytes as u64, "protected file too large");
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max_bytes, "protected file too large");
    Ok(bytes)
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

pub(crate) fn validate_key_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
        "invalid key id"
    );
    Ok(())
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
        let owner = Self::state_owner(&config, development)?;
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
        let db = Self::open_database(&config, development)?;
        db.execute_batch("BEGIN IMMEDIATE;
            INSERT INTO audit(time,id,event) SELECT unixepoch(),id,'uncertain' FROM requests WHERE state IN ('consumed','running');
            UPDATE requests SET state='uncertain' WHERE state IN ('consumed','running');
            INSERT INTO audit(time,id,event) SELECT unixepoch(),id,'cancelled_on_restart' FROM requests WHERE state='pending';
            UPDATE requests SET state='cancelled' WHERE state='pending'; COMMIT;")?;
        Ok(Self {
            config,
            db,
            _lock: StateLock(lock),
            owner,
            development,
            results: HashMap::new(),
        })
    }
    fn state_owner(config: &Config, development: bool) -> Result<u32> {
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
        Ok(owner)
    }

    fn open_database(config: &Config, development: bool) -> Result<Connection> {
        let owner = Self::state_owner(config, development)?;
        let path = config.state_dir.join("state.sqlite3");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error.into()),
        }
        Self::check_private_file(&path, owner)?;
        let mut db = Connection::open(path)?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, envelope TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, key_id TEXT);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, time INTEGER NOT NULL, id TEXT NOT NULL, event TEXT NOT NULL, key_id TEXT);
            CREATE TABLE IF NOT EXISTS revoked_keys(id TEXT PRIMARY KEY);")?;
        let has_output_policy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('requests') WHERE name='share_output')",
            [],
            |row| row.get(0),
        )?;
        if !has_output_policy {
            tx.execute_batch("ALTER TABLE requests ADD COLUMN share_output INTEGER NOT NULL DEFAULT 0 CHECK(share_output IN (0,1));")?;
        }
        tx.commit()?;
        Ok(db)
    }
    fn retire_pending(db: &Connection, key_id: &str) -> Result<()> {
        db.execute("INSERT INTO audit(time,id,event,key_id) SELECT unixepoch(),id,'cancelled_by_enrollment',?1 FROM requests WHERE state='pending'", [key_id])?;
        db.execute(
            "UPDATE requests SET state='cancelled' WHERE state='pending'",
            [],
        )?;
        Ok(())
    }

    pub fn pair_key(config: &Config, development: bool, id: &str, encoded: &str) -> Result<()> {
        use std::io::Write;
        validate_key_id(id)?;
        ApprovalKey::parse(encoded)?;
        let mut db = Self::open_database(config, development)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let keys = config.state_dir.join("keys");
        if !development {
            protected_path(&keys, 0)?;
        }
        let path = keys.join(format!("{id}.pub"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("approving key already exists"),
        }
        // An interrupted pairing must never enable an uncommitted key file.
        tx.execute("INSERT OR IGNORE INTO revoked_keys(id) VALUES(?1)", [id])?;
        Self::retire_pending(&tx, id)?;
        tx.execute("INSERT INTO audit(time,id,event,key_id) VALUES(unixepoch(),'','key_pairing_started',?1)", [id])?;
        tx.commit()?;
        #[cfg(test)]
        enrollment_tests::checkpoint("pair-denied");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        fs::File::open(&keys)?.sync_all()?;
        #[cfg(test)]
        enrollment_tests::checkpoint("pair-file-durable");
        Self::retire_pending(&tx, id)?;
        tx.execute("DELETE FROM revoked_keys WHERE id=?1", [id])?;
        tx.execute(
            "INSERT INTO audit(time,id,event,key_id) VALUES(unixepoch(),'','key_paired',?1)",
            [id],
        )?;
        #[cfg(test)]
        enrollment_tests::checkpoint("pair-before-commit");
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_key(config: &Config, development: bool, id: &str) -> Result<()> {
        validate_key_id(id)?;
        let mut db = Self::open_database(config, development)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR IGNORE INTO revoked_keys(id) VALUES(?1)", [id])?;
        Self::retire_pending(&tx, id)?;
        tx.execute(
            "INSERT INTO audit(time,id,event,key_id) VALUES(unixepoch(),'','key_revoked',?1)",
            [id],
        )?;
        // Commit denial first: a crash or failed file deletion must leave the key revoked.
        tx.commit()?;
        #[cfg(test)]
        enrollment_tests::checkpoint("revoke-denied");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let still_revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE id=?1)",
            [id],
            |row| row.get(0),
        )?;
        if !still_revoked {
            return Ok(());
        }
        let keys = config.state_dir.join("keys");
        if !development {
            protected_path(&keys, 0)?;
        }
        match fs::remove_file(keys.join(format!("{id}.pub"))) {
            Ok(()) => fs::File::open(keys)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        tx.commit()?;
        Ok(())
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
        Self::record_transition(&tx, id, state, key, share_output)?;
        tx.commit()?;
        Ok(())
    }
    fn record_transition(
        db: &Connection,
        id: &str,
        state: State,
        key: Option<&str>,
        share_output: Option<bool>,
    ) -> Result<()> {
        db.execute(
            "UPDATE requests SET state=?2,key_id=COALESCE(?3,key_id),share_output=COALESCE(?4,share_output) WHERE id=?1",
            params![id, state.as_str(), key, share_output],
        )?;
        db.execute(
            "INSERT INTO audit(time,id,event,key_id) VALUES(?1,?2,?3,?4)",
            params![i64::try_from(now())?, id, state.as_str(), key],
        )?;
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
    fn key(&self, id: &str) -> Result<ApprovalKey> {
        validate_key_id(id)?;
        let path = self.config.state_dir.join("keys").join(format!("{id}.pub"));
        Self::check_private_file(&path, self.owner)?;
        let bytes = if self.development {
            fs::read(path)?
        } else {
            read_protected_file(&path, 1024)?
        };
        ApprovalKey::parse(std::str::from_utf8(&bytes)?)
    }
    /// Fixed-time entry point for deterministic fixtures. Live transports use handle_current.
    pub fn handle(&mut self, req: Request, uid: u32, time: u64) -> Result<(Reply, Option<Job>)> {
        self.handle_with_clock(req, uid, || time)
    }
    pub fn handle_current(&mut self, req: Request, uid: u32) -> Result<(Reply, Option<Job>)> {
        self.handle_with_clock(req, uid, now)
    }
    #[cfg(feature = "native-receipt-lab")]
    pub(crate) fn handle_receipt_current(
        &mut self,
        req: Request,
        uid: u32,
    ) -> Result<(Reply, Option<Job>)> {
        self.handle_decision(req, uid, now, true)
    }
    fn handle_with_clock(
        &mut self,
        req: Request,
        uid: u32,
        clock: impl Fn() -> u64,
    ) -> Result<(Reply, Option<Job>)> {
        self.handle_decision(req, uid, clock, false)
    }
    fn handle_decision(
        &mut self,
        req: Request,
        uid: u32,
        clock: impl Fn() -> u64,
        receipt_only: bool,
    ) -> Result<(Reply, Option<Job>)> {
        let req = match req {
            Request::ApproveReceipt {
                id,
                key_id,
                number,
                signature,
                share_output,
            } if receipt_only => Request::Approve {
                id,
                key_id,
                number,
                signature,
                share_output,
            },
            other => {
                ensure!(!receipt_only, "expected a receipt approval");
                other
            }
        };
        let time = clock();
        ensure!(
            uid == self.config.agent_uid || uid == self.config.approver_uid,
            "peer not authorized"
        );
        self.expire(time)?;
        match req {
            Request::ApproveReceipt { .. } => {
                anyhow::bail!("receipt approval requires receipt-only transport")
            }
            Request::RequestExecution { mut spec } => {
                let total: u32 = self
                    .db
                    .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))?;
                ensure!(total < 10_000, "audit capacity reached; administrator must archive and rotate the broker state");
                spec.validate()?;
                ensure!(
                    spec.timeout_secs <= self.config.max_execution_secs,
                    "execution timeout exceeds administrator maximum"
                );
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
                let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
                let time = clock();
                let revoked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE id=?1)",
                    [&key_id],
                    |row| row.get(0),
                )?;
                ensure!(!revoked, "approving key is revoked");
                let (env, state, attempts) = self.load(&id)?;
                ensure!(
                    state == State::Pending && time < env.expires_at,
                    "request is not pending"
                );
                ensure!(time >= env.created_at, "request is not yet valid");
                ensure!(
                    env.spec.timeout_secs <= self.config.max_execution_secs,
                    "execution timeout exceeds administrator maximum"
                );
                let key = self.key(&key_id)?;
                ensure!(signature.len() <= 144, "approval signature is too long");
                let signature = hex::decode(signature)?;
                ensure!(env.version == 2, "unsupported approval version");
                let payload = if receipt_only {
                    env.receipt_approval_payload(share_output)?
                } else {
                    env.approval_payload(share_output)?
                };
                key.verify(&payload, &signature)
                    .context("invalid approval signature")?;
                if number != env.number {
                    self.db
                        .execute("UPDATE requests SET attempts=attempts+1 WHERE id=?1", [&id])?;
                    if attempts >= 2 {
                        Self::record_transition(&tx, &id, State::Cancelled, Some(&key_id), None)?;
                    }
                    tx.commit()?;
                    anyhow::bail!("incorrect confirmation number");
                }
                // Consumption commits before any execution thread is created. Retries never launch twice.
                let time = clock();
                ensure!(
                    time >= env.created_at && time < env.expires_at,
                    "approval outside validity window"
                );
                Self::record_transition(
                    &tx,
                    &id,
                    State::Consumed,
                    Some(&key_id),
                    Some(share_output),
                )?;
                tx.commit()?;
                Ok((
                    Reply::success(serde_json::json!({"id":id,"state":"consumed"})),
                    if receipt_only {
                        None
                    } else {
                        Some(Job {
                            envelope: env,
                            share_output,
                        })
                    },
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

#[cfg(test)]
#[path = "broker_enrollment_tests.rs"]
mod enrollment_tests;

#[cfg(test)]
mod clock_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{cell::Cell, os::unix::fs::PermissionsExt};

    #[test]
    fn approval_rechecks_time_after_lock_and_before_consumption() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.path().join("keys")).unwrap();
        let key = SigningKey::from_bytes(&[29; 32]);
        let path = dir.path().join("keys/test.pub");
        fs::write(&path, hex::encode(key.verifying_key().to_bytes())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let mut broker = Broker::open(
            Config {
                machine_id: uuid::Uuid::new_v4().to_string(),
                agent_uid: uid,
                approver_uid: uid,
                socket_gid: unsafe { libc::getegid() },
                state_dir: dir.path().to_path_buf(),
                socket: dir.path().join("run/socket"),
                approval_ttl_secs: 300,
                max_execution_secs: 300,
            },
            true,
        )
        .unwrap();
        let fixture: crate::protocol::PendingView =
            serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
        let (reply, _) = broker
            .handle(
                Request::RequestExecution {
                    spec: fixture.envelope.spec,
                },
                uid,
                100,
            )
            .unwrap();
        let pending: crate::protocol::PendingView =
            serde_json::from_value(reply.value().unwrap()).unwrap();
        let envelope = pending.envelope;
        let approval = || Request::Approve {
            id: envelope.id.clone(),
            key_id: "test".into(),
            number: envelope.number.clone(),
            share_output: false,
            signature: hex::encode(
                key.sign(&envelope.approval_payload(false).unwrap())
                    .to_bytes(),
            ),
        };
        for times in [[100, 400, 400], [100, 100, 400], [100, 100, 99]] {
            let index = Cell::new(0);
            assert!(broker
                .handle_with_clock(approval(), uid, || {
                    let i = index.get();
                    index.set(i + 1);
                    times[i.min(2)]
                })
                .is_err());
            assert_eq!(broker.load(&envelope.id).unwrap().1, State::Pending);
        }
        let (_, job) = broker.handle(approval(), uid, 101).unwrap();
        assert!(job.is_some());
        drop(job);
    }
}
