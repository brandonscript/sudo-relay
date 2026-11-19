//! Ordinary-user process-crash fixtures; this module is absent from production builds.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const STAGE: &str = "SUDO_RELAY_TEST_ENROLLMENT_STAGE";
const ROOT: &str = "SUDO_RELAY_TEST_ENROLLMENT_ROOT";

pub(super) fn checkpoint(stage: &str) {
    if std::env::var(STAGE).as_deref() != Ok(stage) {
        return;
    }
    let root = PathBuf::from(std::env::var_os(ROOT).expect("test fixture root"));
    fs::write(root.join("checkpoint.tmp"), stage).unwrap();
    fs::rename(root.join("checkpoint.tmp"), root.join("checkpoint")).unwrap();
    loop {
        std::thread::park();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess worker; invoked only by the crash fixture"]
fn enrollment_crash_worker() {
    let Some(root) = std::env::var_os(ROOT) else {
        return;
    };
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let root = PathBuf::from(root);
    let config: Config =
        serde_json::from_slice(&fs::read(root.join("config.json")).unwrap()).unwrap();
    let public = hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes());
    if std::env::var(STAGE).unwrap().starts_with("pair-") {
        Broker::pair_key(&config, true, "test", &public).unwrap();
    } else {
        Broker::revoke_key(&config, true, "test").unwrap();
    }
    panic!("worker missed checkpoint");
}

fn request(broker: &mut Broker, uid: u32) -> Envelope {
    let fixture: crate::protocol::PendingView =
        serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
    let (reply, job) = broker
        .handle(
            Request::RequestExecution {
                spec: fixture.envelope.spec,
            },
            uid,
            100,
        )
        .unwrap();
    assert!(job.is_none());
    serde_json::from_value::<crate::protocol::PendingView>(reply.value().unwrap())
        .unwrap()
        .envelope
}

fn approval(envelope: &Envelope) -> Request {
    let key = SigningKey::from_bytes(&[31; 32]);
    Request::Approve {
        id: envelope.id.clone(),
        key_id: "test".into(),
        number: envelope.number.clone(),
        share_output: false,
        signature: hex::encode(
            key.sign(&envelope.approval_payload(false).unwrap())
                .to_bytes(),
        ),
    }
}

#[test]
fn killed_enrollment_processes_stay_blocked_until_explicit_recovery() {
    let uid = unsafe { libc::geteuid() };
    assert_ne!(uid, 0, "ordinary-user fixture only");
    for stage in [
        "pair-denied",
        "pair-file-durable",
        "pair-before-commit",
        "revoke-denied",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.path().join("keys")).unwrap();
        let config = Config {
            machine_id: uuid::Uuid::new_v4().to_string(),
            agent_uid: uid,
            approver_uid: uid,
            socket_gid: unsafe { libc::getegid() },
            state_dir: root.path().into(),
            socket: root.path().join("run/socket"),
            approval_ttl_secs: 300,
            max_execution_secs: 300,
        };
        fs::write(
            root.path().join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let public = hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes());
        if stage == "revoke-denied" {
            Broker::pair_key(&config, true, "test", &public).unwrap();
        }
        let mut broker = Broker::open(config.clone(), true).unwrap();
        let pending = request(&mut broker, uid);
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "broker::enrollment_tests::enrollment_crash_worker",
                    "--ignored",
                ])
                .env(ROOT, root.path())
                .env(STAGE, stage)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let marker = root.path().join("checkpoint");
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{stage}: worker exited before checkpoint"
            );
            assert!(Instant::now() < deadline, "{stage}: checkpoint timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(marker).unwrap(), stage);
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        // Keep the original broker alive: startup cancellation must not mask the enrollment result.
        assert_eq!(
            broker.load(&pending.id).unwrap().1,
            State::Cancelled,
            "{stage}"
        );
        assert!(
            broker.handle(approval(&pending), uid, 101).is_err(),
            "{stage}"
        );
        let exists = root.path().join("keys/test.pub").exists();
        assert_eq!(exists, stage != "pair-denied", "{stage}");
        let fresh = request(&mut broker, uid);
        assert!(
            broker.handle(approval(&fresh), uid, 101).is_err(),
            "{stage}"
        );
        let blocked: bool = broker
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE id='test')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(blocked, "{stage}");
        drop(broker);
        let mut broker = Broker::open(config.clone(), true).unwrap();
        let after_restart = request(&mut broker, uid);
        assert!(
            broker.handle(approval(&after_restart), uid, 101).is_err(),
            "{stage}"
        );
        Broker::revoke_key(&config, true, "test").unwrap();
        Broker::pair_key(&config, true, "test", &public).unwrap();
        assert!(
            broker.handle(approval(&after_restart), uid, 101).is_err(),
            "{stage}"
        );
        let recovered = request(&mut broker, uid);
        let (_, job) = broker.handle(approval(&recovered), uid, 101).unwrap();
        assert!(job.is_some(), "{stage}: recovery positive control");
        drop(job); // No executor is called in this fixture.
    }
}
