//! These tests run only as root in disposable CI machines, never against an installed service.
use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::{
        fs::{symlink, PermissionsExt},
        process::CommandExt,
    },
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::{Duration, Instant},
};
use sudo_relay::{
    broker::{protected_path, read_protected_file, Config},
    protocol::{Command, PendingView, Request, Spec},
    transport,
};

struct Cleanup {
    dir: PathBuf,
    child: Option<Child>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn probe(config: &Config, uid: u32, operation: &str, request: Option<&str>) {
    let mut command = Process::new(config.socket.parent().unwrap().join("peer-probe"));
    command
        .args([
            "--ignored",
            "--exact",
            "unprivileged_peer_probe",
            "--nocapture",
        ])
        .env("PE_CONFIG", serde_json::to_string(config).unwrap())
        .env("PE_OPERATION", operation)
        .env("PE_APPROVAL", request.unwrap_or(""))
        .current_dir("/");
    let gid = config.socket_gid;
    // Set groups before dropping UID; clearing them afterward resets the GID on macOS.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(1, &gid) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().unwrap();
    assert!(status.success(), "unprivileged peer probe failed");
}
#[test]
#[ignore = "root only; run in a disposable VM/container"]
fn root_broker_enforces_identity_and_protected_paths() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "disposable root test only");
    let parent = if cfg!(target_os = "macos") {
        "/private/var"
    } else {
        "/var/lib"
    };
    let dir = PathBuf::from(parent).join(format!("sudo-relay-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cleanup = Cleanup {
        dir: dir.clone(),
        child: None,
    };
    // Runner home directories may be inaccessible after dropping to the fixture UID.
    let probe_path = dir.join("peer-probe");
    fs::copy(std::env::current_exe().unwrap(), &probe_path).unwrap();
    fs::set_permissions(&probe_path, fs::Permissions::from_mode(0o755)).unwrap();
    let state = dir.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = state.join("keys");
    fs::create_dir(&keys).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let keyfile = keys.join("test.pub");
    fs::write(&keyfile, hex::encode(key.verifying_key().to_bytes())).unwrap();
    fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
    let config = Config {
        machine_id: uuid::Uuid::new_v4().to_string(),
        agent_uid: 10001,
        approver_uid: 10002,
        socket_gid: 10001,
        approval_ttl_secs: 300,
        max_execution_secs: 300,
        state_dir: state,
        socket: dir.join("broker.sock"),
    };
    let host_dir = dir.join("host");
    fs::create_dir(&host_dir).unwrap();
    fs::set_permissions(&host_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let host_key = host_dir.join("host.key");
    fs::write(&host_key, key.to_bytes()).unwrap();
    fs::set_permissions(&host_key, fs::Permissions::from_mode(0o600)).unwrap();
    use std::os::unix::ffi::OsStrExt;
    for path in [&host_dir, &host_key] {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(name.as_ptr(), config.approver_uid, config.socket_gid) },
            0
        );
    }
    let config_path = dir.join("config.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    cleanup.child = Some(
        Process::new(env!("CARGO_BIN_EXE_broker"))
            .arg("serve")
            .arg(config_path)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !config.socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(config.socket.exists());
    probe(&config, 10001, "request", None);
    probe(&config, 10003, "foreign", None);
    // Root is intentionally not a broker client: create/query through authorized peer identities.
    let request_path = dir.join("pending.json");
    // A separate peer creates the request and saves the public envelope for the parent signer.
    fs::write(&request_path, b"").unwrap();
    fs::set_permissions(&request_path, fs::Permissions::from_mode(0o666)).unwrap();
    probe(
        &config,
        10001,
        "save_pending",
        Some(request_path.to_str().unwrap()),
    );
    let pending: PendingView = serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
    let approval = Request::Approve {
        id: pending.envelope.id.clone(),
        key_id: "test".into(),
        number: pending.envelope.number.clone(),
        share_output: true,
        signature: hex::encode(
            key.sign(&pending.envelope.approval_payload(true).unwrap())
                .to_bytes(),
        ),
    };
    let json = serde_json::to_string(&approval).unwrap();
    probe(&config, 10001, "agent_approve", Some(&json));
    probe(&config, 10002, "approve", Some(&json));
    probe(&config, 10002, "replay", Some(&json));
    let writable = dir.join("writable");
    fs::create_dir(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    let link = writable.join("printf");
    symlink("/usr/bin/printf", &link).unwrap();
    assert!(
        protected_path(&link, 0).is_err(),
        "writable original ancestor must not be hidden by canonicalization"
    );
    fs::remove_file(link).unwrap();
}
#[test]
#[ignore = "helper subprocess for disposable root test"]
fn unprivileged_peer_probe() {
    let Ok(raw) = std::env::var("PE_CONFIG") else {
        return;
    };
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let config: Config = serde_json::from_str(&raw).unwrap();
    assert_eq!(unsafe { libc::getegid() }, config.socket_gid);
    assert!(fs::read(config.state_dir.join("keys/test.pub")).is_err());
    assert!(fs::write(config.state_dir.join("keys/evil.pub"), "evil").is_err());
    let signing_key = config.socket.parent().unwrap().join("host/host.key");
    if unsafe { libc::geteuid() } == config.approver_uid {
        assert!(fs::read(signing_key).is_ok());
    } else {
        assert!(fs::read(signing_key).is_err());
    }
    let spec = Spec {
        command: Command::Argv {
            argv: vec!["/usr/bin/printf".into(), "root integration".into()],
        },
        env: BTreeMap::new(),
        reason: "Disposable root test".into(),
        timeout_secs: 1,
        output_needed: false,
    };
    let op = std::env::var("PE_OPERATION").unwrap();
    if op == "foreign" {
        assert!(transport::call(&config.socket, &Request::RequestExecution { spec }).is_err());
        return;
    }
    if op == "request" || op == "save_pending" {
        let value = transport::call(&config.socket, &Request::RequestExecution { spec }).unwrap();
        if op == "save_pending" {
            fs::write(
                std::env::var("PE_APPROVAL").unwrap(),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        }
        if op == "request" {
            let id = value["envelope"]["id"].as_str().unwrap().to_owned();
            transport::call(&config.socket, &Request::CancelExecution { id }).unwrap();
        }
        return;
    }
    let req: Request = serde_json::from_str(&std::env::var("PE_APPROVAL").unwrap()).unwrap();
    let id = if let Request::Approve { id, .. } = &req {
        id.clone()
    } else {
        panic!()
    };
    let reply = transport::call(&config.socket, &req);
    if op == "agent_approve" || op == "replay" {
        assert!(reply.is_err());
        return;
    }
    reply.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state =
            transport::call(&config.socket, &Request::ExecutionStatus { id: id.clone() }).unwrap();
        if state["state"] == "complete" {
            assert_eq!(state["outcome"]["stdout"], "root integration");
            assert_eq!(state["outcome"]["exit_code"], 0);
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "root only; run in disposable macOS CI"]
fn root_owned_paths_reject_acl_writable_ancestors() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let dir =
        PathBuf::from("/private/var").join(format!("sudo-relay-acl-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let _cleanup = Cleanup {
        dir: dir.clone(),
        child: None,
    };
    let file = dir.join("trust.pub");
    fs::write(&file, "public test data").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    protected_path(&file, 0).unwrap();
    for target in [&dir, &file] {
        let permissions = if target == &dir {
            "everyone allow add_file,delete_child"
        } else {
            "everyone allow write"
        };
        assert!(Process::new("/bin/chmod")
            .args(["+a", permissions])
            .arg(target)
            .status()
            .unwrap()
            .success());
        let result = protected_path(&file, 0);
        let read_result = read_protected_file(&file, 1024);
        assert!(Process::new("/bin/chmod")
            .arg("-N")
            .arg(target)
            .status()
            .unwrap()
            .success());
        assert!(result.unwrap_err().to_string().contains("extended ACL"));
        assert!(read_result
            .unwrap_err()
            .to_string()
            .contains("extended ACL"));
        protected_path(&file, 0).unwrap();
    }
}

#[test]
#[ignore = "root only; run in disposable CI machines"]
fn protected_reads_reject_unsafe_or_unbounded_files() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let parent = if cfg!(target_os = "macos") {
        "/private/var"
    } else {
        "/var/lib"
    };
    let dir = PathBuf::from(parent).join(format!("sudo-relay-read-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let _cleanup = Cleanup {
        dir: dir.clone(),
        child: None,
    };
    let file = dir.join("policy");
    fs::write(&file, b"test policy").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_protected_file(&file, 11).unwrap(), b"test policy");
    assert!(read_protected_file(&file, 10).is_err());
    assert!(read_protected_file(&file, 0).is_err());
    assert!(read_protected_file(&file, usize::MAX).is_err());
    assert!(read_protected_file(&dir, 1024).is_err());
    for target in [&dir, &file] {
        fs::set_permissions(target, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_protected_file(&file, 1024).is_err());
        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let fifo = dir.join("fifo");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    assert!(read_protected_file(&fifo, 1024).is_err());
    let file_c = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(file_c.as_ptr(), 10001, 10001) }, 0);
    assert!(read_protected_file(&file, 1024).is_err());
}

#[test]
fn protected_reads_reject_user_owned_policy() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy");
    fs::write(&file, b"test policy").unwrap();
    assert!(read_protected_file(&file, 1024).is_err());
}
