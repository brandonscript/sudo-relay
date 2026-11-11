use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use sudo_relay::{
    broker::{Broker, Config},
    execution,
    protocol::{Command, Envelope, PendingView, Request, Spec},
};
use tempfile::TempDir;

struct Setup {
    dir: TempDir,
    config: Config,
    key: SigningKey,
}
impl Setup {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.path().join("keys")).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let path = dir.path().join("keys/test.pub");
        fs::write(&path, hex::encode(key.verifying_key().to_bytes())).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        Self {
            config: Config {
                machine_id: uuid::Uuid::new_v4().to_string(),
                agent_uid: uid,
                approver_uid: uid,
                socket_gid: unsafe { libc::getegid() },
                approval_ttl_secs: 300,
                max_execution_secs: 300,
                state_dir: dir.path().into(),
                socket: dir.path().join("socket-dir/socket"),
            },
            dir,
            key,
        }
    }
    fn broker(&self) -> Broker {
        Broker::open(self.config.clone(), true).unwrap()
    }
    fn request(&self, broker: &mut Broker) -> Envelope {
        let (reply, job) = broker
            .handle(
                Request::RequestExecution { spec: spec() },
                self.config.agent_uid,
                100,
            )
            .unwrap();
        assert!(job.is_none());
        serde_json::from_value::<PendingView>(reply.value().unwrap())
            .unwrap()
            .envelope
    }
    fn approval(&self, env: &Envelope) -> Request {
        self.approval_with_output(env, true)
    }
    fn approval_with_output(&self, env: &Envelope, share_output: bool) -> Request {
        Request::Approve {
            id: env.id.clone(),
            key_id: "test".into(),
            number: env.number.clone(),
            share_output,
            signature: hex::encode(
                self.key
                    .sign(&env.approval_payload(share_output).unwrap())
                    .to_bytes(),
            ),
        }
    }
}
fn spec() -> Spec {
    Spec {
        command: Command::Argv {
            argv: vec!["/usr/bin/printf".into(), "hello".into()],
        },
        env: BTreeMap::new(),
        reason: "Print hello".into(),
        timeout_secs: 1,
        output_needed: false,
    }
}
fn state(broker: &mut Broker, id: &str, uid: u32, time: u64) -> String {
    broker
        .handle(Request::ExecutionStatus { id: id.into() }, uid, time)
        .unwrap()
        .0
        .value()
        .unwrap()["state"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn request_never_executes_and_replay_never_launches_twice() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    assert_eq!(state(&mut b, &env.id, s.config.agent_uid, 100), "pending");
    assert!(b
        .handle(s.approval(&env), s.config.agent_uid, 101)
        .unwrap()
        .1
        .is_some());
    assert!(b.handle(s.approval(&env), s.config.agent_uid, 102).is_err());
}
#[test]
fn forged_wrong_key_changed_command_and_cross_machine_approvals_fail() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    for index in 0..3 {
        let mut changed = env.clone();
        match index {
            0 => changed.spec.reason.push('!'),
            1 => {
                if let Command::Argv { argv } = &mut changed.spec.command {
                    argv.push("changed".into());
                }
            }
            _ => changed.spec.timeout_secs = 2,
        }
        assert!(b
            .handle(s.approval(&changed), s.config.agent_uid, 101)
            .is_err());
    }
    let mut wrong = env.clone();
    wrong.machine_id = uuid::Uuid::new_v4().to_string();
    assert!(b
        .handle(s.approval(&wrong), s.config.agent_uid, 101)
        .is_err());
    let req = Request::Approve {
        id: env.id.clone(),
        key_id: "test".into(),
        number: env.number.clone(),
        share_output: true,
        signature: hex::encode(
            SigningKey::from_bytes(&[8; 32])
                .sign(&env.approval_payload(true).unwrap())
                .to_bytes(),
        ),
    };
    assert!(b.handle(req, s.config.agent_uid, 101).is_err());
    assert_eq!(state(&mut b, &env.id, s.config.agent_uid, 101), "pending");
}
#[test]
fn expiry_cancellation_and_revocation_deny_execution() {
    for mode in ["expired", "cancelled", "revoked"] {
        let s = Setup::new();
        let mut b = s.broker();
        let env = s.request(&mut b);
        let time = if mode == "expired" { 400 } else { 101 };
        if mode == "cancelled" {
            b.handle(
                Request::CancelExecution { id: env.id.clone() },
                s.config.agent_uid,
                101,
            )
            .unwrap();
        }
        if mode == "revoked" {
            fs::remove_file(s.dir.path().join("keys/test.pub")).unwrap();
        }
        assert!(b
            .handle(s.approval(&env), s.config.agent_uid, time)
            .is_err());
    }
}
#[test]
fn four_hosts_isolate_colliding_requests_and_key_revocation() {
    let setups: Vec<_> = (0..4).map(|_| Setup::new()).collect();
    let mut brokers: Vec<_> = setups.iter().map(Setup::broker).collect();
    let common = Envelope::new(&setups[0].config.machine_id, spec(), 100, 300).unwrap();
    let envelopes: Vec<_> = setups
        .iter()
        .map(|setup| {
            let mut envelope = common.clone();
            envelope.machine_id = setup.config.machine_id.clone();
            // Controller-created collision: only machine identity differs, not ID, nonce or command.
            let db = rusqlite::Connection::open(setup.dir.path().join("state.sqlite3")).unwrap();
            db.execute(
                "INSERT INTO requests(id,envelope,state) VALUES(?1,?2,'pending')",
                rusqlite::params![envelope.id, serde_json::to_string(&envelope).unwrap()],
            )
            .unwrap();
            envelope
        })
        .collect();
    for (source, setup) in setups.iter().enumerate() {
        for (target, broker) in brokers.iter_mut().enumerate() {
            if source == target {
                continue;
            }
            let error = broker
                .handle(
                    setup.approval(&envelopes[source]),
                    setup.config.approver_uid,
                    101,
                )
                .err()
                .expect("another host's signature must be rejected");
            assert!(error.to_string().contains("invalid approval signature"));
            assert_eq!(
                state(broker, &common.id, setup.config.agent_uid, 101),
                "pending"
            );
        }
    }
    fs::remove_file(setups[0].dir.path().join("keys/test.pub")).unwrap();
    assert!(brokers[0]
        .handle(
            setups[0].approval(&envelopes[0]),
            setups[0].config.approver_uid,
            102
        )
        .is_err());
    for index in 1..4 {
        let setup = &setups[index];
        let envelope = &envelopes[index];
        let broker = &mut brokers[index];
        let (_, job) = broker
            .handle(setup.approval(envelope), setup.config.approver_uid, 102)
            .unwrap();
        // Inspect authorization only; never call the executor or start a transport listener.
        assert_eq!(job.unwrap().envelope.machine_id, setup.config.machine_id);
        assert_eq!(
            state(broker, &common.id, setup.config.agent_uid, 102),
            "consumed"
        );
        assert!(broker
            .handle(setup.approval(envelope), setup.config.approver_uid, 103)
            .is_err());
    }
    assert_eq!(
        state(&mut brokers[0], &common.id, setups[0].config.agent_uid, 103),
        "pending"
    );
}
#[test]
fn three_signed_wrong_number_attempts_cancel() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    for _ in 0..3 {
        let mut req = s.approval(&env);
        if let Request::Approve { number, .. } = &mut req {
            *number = "00".into();
        }
        assert!(b.handle(req, s.config.agent_uid, 101).is_err());
    }
    assert_eq!(state(&mut b, &env.id, s.config.agent_uid, 101), "cancelled");
    assert!(b.handle(s.approval(&env), s.config.agent_uid, 101).is_err());
}
#[test]
fn pending_restart_cancels_and_consumed_restart_is_uncertain() {
    for consumed in [false, true] {
        let s = Setup::new();
        let mut b = s.broker();
        let env = s.request(&mut b);
        if consumed {
            b.handle(s.approval(&env), s.config.agent_uid, 101).unwrap();
        }
        drop(b);
        let mut b = s.broker();
        assert_eq!(
            state(&mut b, &env.id, s.config.agent_uid, 102),
            if consumed { "uncertain" } else { "cancelled" }
        );
        assert!(b.handle(s.approval(&env), s.config.agent_uid, 102).is_err());
    }
}
#[test]
fn only_one_pending_request_and_one_state_owner() {
    let s = Setup::new();
    let mut b = s.broker();
    s.request(&mut b);
    assert!(b
        .handle(
            Request::RequestExecution { spec: spec() },
            s.config.agent_uid,
            100
        )
        .is_err());
    assert!(Broker::open(s.config.clone(), true).is_err());
}
#[test]
fn concurrent_approvals_only_consume_once() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    let shared = Arc::new(Mutex::new(b));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let b = shared.clone();
            let req = s.approval(&env);
            let uid = s.config.agent_uid;
            std::thread::spawn(move || b.lock().unwrap().handle(req, uid, 101).is_ok())
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|v| *v)
            .count(),
        1
    );
}
#[test]
fn cancellation_race_has_one_winner() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    let shared = Arc::new(Mutex::new(b));
    let b = shared.clone();
    let uid = s.config.agent_uid;
    let id = env.id.clone();
    let cancel = std::thread::spawn(move || {
        b.lock()
            .unwrap()
            .handle(Request::CancelExecution { id }, uid, 101)
            .is_ok()
    });
    let approved = shared
        .lock()
        .unwrap()
        .handle(s.approval(&env), uid, 101)
        .is_ok();
    assert_ne!(cancel.join().unwrap(), approved);
}
#[test]
fn bad_peer_cannot_request_or_approve() {
    let s = Setup::new();
    let mut b = s.broker();
    assert!(b
        .handle(
            Request::RequestExecution { spec: spec() },
            s.config.agent_uid + 1,
            100
        )
        .is_err());
    let env = s.request(&mut b);
    assert!(b
        .handle(s.approval(&env), s.config.agent_uid + 1, 101)
        .is_err());
}
#[test]
fn unsafe_input_rejected_without_truncating() {
    let mut s = spec();
    s.reason = "a".repeat(17000);
    assert!(s.validate().is_err());
    s.reason = "safe".into();
    s.env.insert("LD_PRELOAD".into(), "evil".into());
    assert!(s.validate().is_err());
    s.env.clear();
    s.command = Command::Argv {
        argv: vec!["/bin/echo".into(), "\u{202e}hidden".into()],
    };
    assert!(s.validate().is_err());
    s.command = Command::Argv {
        argv: vec!["echo".into()],
    };
    assert!(s.validate().is_err());
}
#[test]
fn cbor_matches_typescript_fixture() {
    let value: PendingView = serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
    assert_eq!(
        value.envelope.view().unwrap().signing_payload,
        value.signing_payload
    );
    assert_eq!(value.envelope.view().unwrap().digest, value.digest);
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
    for (share, field) in [
        (true, "approval_payload_shared"),
        (false, "approval_payload_withheld"),
    ] {
        assert_eq!(
            hex::encode(value.envelope.approval_payload(share).unwrap()),
            raw[field].as_str().unwrap()
        );
    }
}
#[test]
fn script_snapshot_output_and_environment() {
    let s = Setup::new();
    let mut request = spec();
    request.command = Command::Script {
        interpreter: "/bin/sh".into(),
        script: "printf '%s|%s' frozen \"${LD_PRELOAD-unset}\"".into(),
    };
    let env = Envelope::new(
        &s.config.machine_id,
        request,
        100,
        s.config.approval_ttl_secs,
    )
    .unwrap();
    let result = execution::execute(&env, s.dir.path(), true, true);
    assert_eq!(result.stdout, "frozen|unset");
    assert_eq!(result.exit_code, Some(0));
    assert!(!s.dir.path().join(format!("{}.script", env.id)).exists());
}
#[test]
fn timeout_and_output_are_bounded() {
    let s = Setup::new();
    let mut request = spec();
    request.command = Command::Script {
        interpreter: "/bin/sh".into(),
        script: "while :; do printf 'long output'; done".into(),
    };
    let env = Envelope::new(
        &s.config.machine_id,
        request,
        100,
        s.config.approval_ttl_secs,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let result = execution::execute(&env, s.dir.path(), true, true);
    assert!(result.timed_out && result.truncated);
    assert!(result.stdout.len() <= 1024 * 1024);
    assert!(start.elapsed().as_secs() < 5);
}
#[test]
fn status_has_no_persistent_output() {
    let s = Setup::new();
    let mut b = s.broker();
    let env = s.request(&mut b);
    b.handle(s.approval(&env), s.config.agent_uid, 101).unwrap();
    b.finish(&env.id, execution::Outcome::error("SECRET_OUTPUT_MARKER"))
        .unwrap();
    drop(b);
    let bytes = fs::read(s.dir.path().join("state.sqlite3")).unwrap();
    assert!(!bytes
        .windows(b"SECRET_OUTPUT_MARKER".len())
        .any(|x| x == b"SECRET_OUTPUT_MARKER"));
}

#[test]
fn canonical_executable_is_frozen_before_display() {
    use std::os::unix::fs::symlink;
    let s = Setup::new();
    let link = s.dir.path().join("command");
    symlink("/usr/bin/printf", &link).unwrap();
    let mut request = spec();
    request.command = Command::Argv {
        argv: vec![link.display().to_string(), "%s".into(), "SAFE".into()],
    };
    let mut broker = s.broker();
    let view: PendingView = serde_json::from_value(
        broker
            .handle(
                Request::RequestExecution { spec: request },
                s.config.agent_uid,
                100,
            )
            .unwrap()
            .0
            .value()
            .unwrap(),
    )
    .unwrap();
    fs::remove_file(&link).unwrap();
    symlink("/bin/sh", &link).unwrap();
    let outcome = execution::execute(&view.envelope, s.dir.path(), true, true);
    assert_eq!(outcome.stdout, "SAFE");
    if let Command::Argv { argv } = view.envelope.spec.command {
        assert_ne!(argv[0], link.display().to_string());
    }
}

#[test]
fn audit_capacity_fails_closed() {
    let s = Setup::new();
    let mut broker = s.broker();
    let mut db = rusqlite::Connection::open(s.dir.path().join("state.sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    for id in 0..10_000 {
        tx.execute(
            "INSERT INTO requests(id,envelope,state) VALUES(?1,'{}','cancelled')",
            [id.to_string()],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let error = broker
        .handle(
            Request::RequestExecution { spec: spec() },
            s.config.agent_uid,
            100,
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("capacity"));
}

#[test]
fn approval_expiry_is_broker_configured_signed_and_enforced() {
    for ttl in [1, 300, 900, 86_400] {
        let mut s = Setup::new();
        s.config.approval_ttl_secs = ttl;
        let mut broker = s.broker();
        let env = s.request(&mut broker);
        assert_eq!(env.expires_at, 100 + ttl);
        let mut changed = env.clone();
        changed.expires_at += 1;
        assert!(broker
            .handle(s.approval(&changed), s.config.agent_uid, 100)
            .is_err());
        assert!(broker
            .handle(s.approval(&env), s.config.agent_uid, 100 + ttl)
            .is_err());
        assert_eq!(
            state(&mut broker, &env.id, s.config.agent_uid, 100 + ttl),
            "expired"
        );
    }
}
#[test]
fn approval_config_is_backward_compatible_and_bounded() {
    let s = Setup::new();
    let mut json = serde_json::to_value(&s.config).unwrap();
    json.as_object_mut().unwrap().remove("approval_ttl_secs");
    let mut config: Config = serde_json::from_value(json).unwrap();
    assert_eq!(config.approval_ttl_secs, 300);
    config.validate(true).unwrap();
    for ttl in [0, 86_401, u64::MAX] {
        config.approval_ttl_secs = ttl;
        assert!(config.validate(true).is_err());
    }
    assert!(Envelope::new(&s.config.machine_id, spec(), u64::MAX, 300).is_err());
}

#[test]
fn production_requires_distinct_unprivileged_identities() {
    let mut config = Setup::new().config;
    config.agent_uid = 10001;
    config.approver_uid = 10002;
    config.validate(false).unwrap();
    config.approver_uid = config.agent_uid;
    assert!(config.validate(false).is_err());
    config.validate(true).unwrap();
    for (agent, approver) in [(0, 10002), (10001, 0)] {
        config.agent_uid = agent;
        config.approver_uid = approver;
        assert!(config.validate(false).is_err());
    }
}

#[test]
fn signed_output_choice_cannot_be_changed_or_omitted() {
    let s = Setup::new();
    let mut broker = s.broker();
    let env = s.request(&mut broker);
    let mut tampered = s.approval_with_output(&env, false);
    if let Request::Approve { share_output, .. } = &mut tampered {
        *share_output = true;
    }
    assert!(broker.handle(tampered, s.config.agent_uid, 101).is_err());
    let mut json = serde_json::to_value(s.approval_with_output(&env, false)).unwrap();
    json.as_object_mut().unwrap().remove("share_output");
    assert!(serde_json::from_value::<Request>(json).is_err());
    let mut changed = env.clone();
    changed.spec.output_needed = true;
    assert!(broker
        .handle(
            s.approval_with_output(&changed, false),
            s.config.agent_uid,
            101
        )
        .is_err());
    assert_eq!(
        state(&mut broker, &env.id, s.config.agent_uid, 101),
        "pending"
    );
    broker
        .handle(s.approval_with_output(&env, false), s.config.agent_uid, 101)
        .unwrap();
}

#[test]
fn broker_enforces_output_choice_even_when_agent_needs_it() {
    for share in [false, true] {
        for needed in [false, true] {
            let s = Setup::new();
            let mut broker = s.broker();
            let mut request = spec();
            request.output_needed = needed;
            let (reply, _) = broker
                .handle(
                    Request::RequestExecution { spec: request },
                    s.config.agent_uid,
                    100,
                )
                .unwrap();
            let env: Envelope = serde_json::from_value::<PendingView>(reply.value().unwrap())
                .unwrap()
                .envelope;
            broker
                .handle(s.approval_with_output(&env, share), s.config.agent_uid, 101)
                .unwrap();
            let mut result = execution::Outcome::error("PRIVATE_ERROR");
            result.stdout = "PRIVATE_STDOUT".into();
            result.stderr = "PRIVATE_STDERR".into();
            result.cleanup_error = Some("PRIVATE_CLEANUP".into());
            result.exit_code = Some(7);
            broker.finish(&env.id, result).unwrap();
            let status = broker
                .handle(
                    Request::ExecutionStatus { id: env.id.clone() },
                    s.config.agent_uid,
                    102,
                )
                .unwrap()
                .0
                .value()
                .unwrap();
            assert_eq!(status["output_shared"], share);
            assert_eq!(status["outcome"]["exit_code"], 7);
            assert_eq!(status.to_string().contains("PRIVATE_"), share);
            drop(broker);
            let mut broker = s.broker();
            let status = broker
                .handle(
                    Request::ExecutionStatus { id: env.id.clone() },
                    s.config.agent_uid,
                    103,
                )
                .unwrap()
                .0
                .value()
                .unwrap();
            assert_eq!(status["output_shared"], share);
            assert!(status["outcome"].is_null());
            let bytes = fs::read(s.dir.path().join("state.sqlite3")).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_"));
        }
    }
}

#[test]
fn capture_disabled_discards_both_streams_but_keeps_exit_status() {
    let s = Setup::new();
    let mut request = spec();
    request.command = Command::Script {
        interpreter: "/bin/sh".into(),
        script: "printf PRIVATE_STDOUT; printf PRIVATE_STDERR >&2; exit 7".into(),
    };
    let env = Envelope::new(&s.config.machine_id, request, 100, 300).unwrap();
    let result = execution::execute(&env, s.dir.path(), true, false);
    assert_eq!(result.stdout, "");
    assert_eq!(result.stderr, "");
    assert_eq!(result.exit_code, Some(7));
    assert!(!result.truncated);
}

#[test]
fn old_ledger_gets_withholding_default() {
    let s = Setup::new();
    drop(s.broker());
    let db = rusqlite::Connection::open(s.dir.path().join("state.sqlite3")).unwrap();
    db.execute_batch("ALTER TABLE requests DROP COLUMN share_output;")
        .unwrap();
    drop(db);
    let mut broker = s.broker();
    let env = s.request(&mut broker);
    let status = broker
        .handle(
            Request::ExecutionStatus { id: env.id },
            s.config.agent_uid,
            101,
        )
        .unwrap()
        .0
        .value()
        .unwrap();
    assert_eq!(status["output_shared"], false);
}

#[test]
fn execution_limit_is_admin_bounded_signed_and_independent_of_approval_expiry() {
    for maximum in [1, 300, 3600, 86_400] {
        let mut setup = Setup::new();
        setup.config.max_execution_secs = maximum;
        let mut broker = setup.broker();
        let mut request = spec();
        request.timeout_secs = maximum + 1;
        assert!(broker
            .handle(
                Request::RequestExecution {
                    spec: request.clone()
                },
                setup.config.agent_uid,
                100
            )
            .is_err());
        request.timeout_secs = maximum;
        let (reply, job) = broker
            .handle(
                Request::RequestExecution { spec: request },
                setup.config.agent_uid,
                100,
            )
            .unwrap();
        assert!(job.is_none());
        let envelope = serde_json::from_value::<PendingView>(reply.value().unwrap())
            .unwrap()
            .envelope;
        assert_eq!(envelope.spec.timeout_secs, maximum);
        assert_eq!(envelope.expires_at, 400);
        let mut changed = envelope.clone();
        changed.spec.timeout_secs += 1;
        assert!(broker
            .handle(setup.approval(&changed), setup.config.approver_uid, 101)
            .is_err());
        if maximum > 1 {
            broker.config.max_execution_secs = maximum - 1;
            assert!(broker
                .handle(setup.approval(&envelope), setup.config.approver_uid, 101)
                .is_err());
            assert_eq!(
                state(&mut broker, &envelope.id, setup.config.agent_uid, 101),
                "pending"
            );
            broker.config.max_execution_secs = maximum;
        }
        let (_, job) = broker
            .handle(setup.approval(&envelope), setup.config.approver_uid, 101)
            .unwrap();
        // Inspect the frozen limit without invoking the executor.
        assert_eq!(job.unwrap().envelope.spec.timeout_secs, maximum);
    }
}

#[test]
fn execution_limit_configuration_preserves_old_defaults_and_rejects_unbounded_values() {
    let setup = Setup::new();
    let mut value = serde_json::to_value(&setup.config).unwrap();
    value.as_object_mut().unwrap().remove("max_execution_secs");
    let mut config: Config = serde_json::from_value(value).unwrap();
    assert_eq!(config.max_execution_secs, 300);
    config.validate(true).unwrap();
    for maximum in [0, 86_401, u64::MAX] {
        config.max_execution_secs = maximum;
        assert!(config.validate(true).is_err());
    }
}
