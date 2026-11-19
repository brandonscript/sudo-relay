//! Explicit disposable-Linux execution lab. Never accepts receipt enrollment.
use crate::{
    approval_key::ApprovalKey,
    broker::read_protected_file,
    protocol::{Command, Envelope, Reply, Request},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u8,
    purpose: String,
    approver_uid: u32,
    machine_id: String,
    machine_name: String,
    operating_system: String,
    account: String,
    signing_key: String,
    signing_key_id: String,
    port: u16,
    #[serde(default)]
    ssh_user: Option<String>,
    known_hosts: PathBuf,
    identity: PathBuf,
}
fn known_hosts_option(path: &Path) -> Result<String> {
    let path = path.to_str().context("host pin path must be UTF-8")?;
    ensure!(
        !path
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\'),
        "unsupported host pin path"
    );
    // OpenSSH parses this option as a list even when argv already keeps it together.
    Ok(format!("UserKnownHostsFile=\"{path}\""))
}

impl Enrollment {
    fn validate(&self, uid: u32) -> Result<()> {
        ensure!(
            self.version == 1
                && matches!(
                    self.purpose.as_str(),
                    "disposable-linux-execution-v1"
                        | "disposable-linux-vm-execution-v1"
                        | "linux-developer-preview-v1"
                ),
            "wrong enrollment purpose"
        );
        ensure!(
            uid != 0 && self.approver_uid == uid,
            "wrong reviewer account"
        );
        ensure!(
            self.port != 0 && self.known_hosts.is_absolute() && self.identity.is_absolute(),
            "invalid SSH target"
        );
        ensure!(
            self.purpose != "linux-developer-preview-v1" || self.ssh_user.is_some(),
            "explicit preview SSH account required"
        );
        let ssh_user = self.ssh_user.as_deref().unwrap_or("approver");
        ensure!(
            ssh_user != "root"
                && !ssh_user.starts_with('-')
                && !ssh_user.is_empty()
                && ssh_user.len() <= 64
                && ssh_user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid SSH review account"
        );
        uuid::Uuid::parse_str(&self.machine_id)?;
        ensure!(
            matches!(ApprovalKey::parse(&self.signing_key)?, ApprovalKey::P256(_)),
            "P-256 required"
        );
        crate::broker::validate_key_id(&self.signing_key_id)?;
        for label in [&self.machine_name, &self.operating_system, &self.account] {
            ensure!(
                !label.is_empty()
                    && label.len() <= 100
                    && label.bytes().all(|b| (32..=126).contains(&b)),
                "invalid label"
            );
        }
        Ok(())
    }

    fn call(&self, request: Request) -> Result<Value> {
        let pin = read_protected_file(&self.known_hosts, 4096)?;
        let pin = std::str::from_utf8(&pin)?.trim();
        ensure!(
            pin.starts_with("sudo-relay-linux ssh-ed25519 ") && pin.lines().count() == 1,
            "invalid host pin"
        );
        // Transport identity is not an approval key; it only opens the forced channel.
        read_protected_file(&self.identity, 4096)?;
        let mut child = Process::new("/usr/bin/ssh")
            .env_clear()
            .args(["-F", "/dev/null", "-T"])
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "HostKeyAlias=sudo-relay-linux",
            ])
            .arg("-o")
            .arg(known_hosts_option(&self.known_hosts)?)
            .args([
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
            ])
            .args([
                "-o",
                "ForwardAgent=no",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "PermitLocalCommand=no",
            ])
            .args([
                "-o",
                "ProxyCommand=none",
                "-o",
                "ProxyJump=none",
                "-o",
                "ControlPath=none",
                "-o",
                "ControlMaster=no",
            ])
            .args(["-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1"])
            .arg("-i")
            .arg(&self.identity)
            .arg("-p")
            .arg(self.port.to_string())
            .arg(format!(
                "{}@127.0.0.1",
                self.ssh_user.as_deref().unwrap_or("approver")
            ))
            .arg("review")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let result = (|| -> Result<Value> {
            let bytes = serde_json::to_vec(&request)?;
            ensure!(bytes.len() <= 4096, "submission too large");
            child.stdin.take().context("SSH stdin")?.write_all(&bytes)?;
            let stdout = child.stdout.take().context("SSH stdout")?;
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.take(131073).read_to_end(&mut bytes).map(|_| bytes)
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    anyhow::bail!("SSH deadline exceeded; approval outcome may be unknown");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let bytes = reader
                .join()
                .map_err(|_| anyhow::anyhow!("SSH reader failed"))??;
            ensure!(
                status.success() && bytes.len() <= 131072,
                "SSH response failed or oversized"
            );
            let reply: Reply = serde_json::from_slice(&bytes)?;
            reply.value()
        })();
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "operation", rename_all = "snake_case")]
enum Operation {
    Fetch {
        enrollment: PathBuf,
        id: String,
    },
    Approve {
        enrollment: PathBuf,
        id: String,
        signature: String,
        share_output: bool,
    },
    Cancel {
        enrollment: PathBuf,
        id: String,
    },
}

fn prepare(
    enrollment: &Enrollment,
    id: &str,
    status: &Value,
    now: u64,
) -> Result<(Envelope, Value)> {
    ensure!(
        status["receipt_only"] != true && status["id"] == id && status["state"] == "pending",
        "not pending execution"
    );
    let pending = &status["pending"];
    let review: Value = serde_json::from_slice(&crate::native_review::prepare(
        &serde_json::to_vec(pending)?,
        &enrollment.machine_id,
        now,
    )?)?;
    let envelope: Envelope = serde_json::from_value(review["envelope"].clone())?;
    ensure!(
        envelope.id == id
            && matches!(&envelope.spec.command, Command::Argv { argv } if argv == &["/usr/bin/id", "-u"])
            && envelope.spec.env.is_empty()
            && envelope.spec.timeout_secs <= 30,
        "outside fixed Linux trial"
    );
    Ok((
        envelope,
        json!({"enrollment": enrollment, "pending_json":serde_json::to_string(pending)?}),
    ))
}

fn handle(
    operation: Operation,
    enrollment: &Enrollment,
    mut call: impl FnMut(Request) -> Result<Value>,
    now: u64,
) -> Result<Value> {
    let id = match &operation {
        Operation::Fetch { id, .. }
        | Operation::Approve { id, .. }
        | Operation::Cancel { id, .. } => id,
    };
    let status = call(Request::ExecutionStatus { id: id.clone() })?;
    if matches!(&operation, Operation::Cancel { .. }) {
        let closed = |value: &Value| {
            value["id"] == id.as_str()
                && value["receipt_only"] != true
                && matches!(value["state"].as_str(), Some("cancelled" | "expired"))
        };
        if closed(&status) {
            return Ok(json!({"closed":true,"state":status["state"]}));
        }
        ensure!(
            status["id"] == id.as_str()
                && status["receipt_only"] != true
                && status["state"] == "pending",
            "review cannot be cancelled"
        );
        let reply = match call(Request::CancelExecution { id: id.clone() }) {
            Ok(reply) => reply,
            Err(error) => {
                // A remote cancellation or expiry may have raced the first status read.
                if let Ok(status) = call(Request::ExecutionStatus { id: id.clone() }) {
                    if closed(&status) {
                        return Ok(json!({"closed":true,"state":status["state"]}));
                    }
                }
                return Err(error);
            }
        };
        ensure!(
            reply["id"] == id.as_str() && reply["state"] == "cancelled",
            "cancellation unconfirmed"
        );
        return Ok(json!({"closed":true,"state":"cancelled"}));
    }
    let (envelope, fetched) = prepare(enrollment, id, &status, now)?;
    match operation {
        Operation::Fetch { .. } => Ok(fetched),
        Operation::Cancel { .. } => unreachable!("handled before pending review preparation"),
        Operation::Approve {
            id,
            signature,
            share_output,
            ..
        } => {
            ensure!(signature.len() <= 144, "invalid signature size");
            ApprovalKey::parse(&enrollment.signing_key)?.verify(
                &envelope.approval_payload(share_output)?,
                &hex::decode(&signature)?,
            )?;
            let reply = call(Request::Approve {
                id: id.clone(),
                key_id: enrollment.signing_key_id.clone(),
                number: envelope.number,
                signature,
                share_output,
            })?;
            ensure!(
                reply["id"] == id && reply["state"] == "consumed",
                "approval acknowledgement unconfirmed"
            );
            Ok(json!({"approved":true}))
        }
    }
}

fn dispatch(input: &[u8]) -> Result<Vec<u8>> {
    let operation: Operation = serde_json::from_slice(input)?;
    let path = match &operation {
        Operation::Fetch { enrollment, .. }
        | Operation::Approve { enrollment, .. }
        | Operation::Cancel { enrollment, .. } => enrollment,
    };
    ensure!(path.is_absolute(), "absolute enrollment required");
    let enrollment: Enrollment =
        serde_json::from_slice(&read_protected_file(Path::new(path), 4096)?)?;
    enrollment.validate(unsafe { libc::geteuid() })?;
    Ok(serde_json::to_vec(&handle(
        operation,
        &enrollment,
        |request| enrollment.call(request),
        crate::broker::now(),
    )?)?)
}

/// Explicit execution-lab bridge. No signing or automatic retry.
/// # Safety
/// Input and output must reference disjoint readable/writable buffers of the given sizes.
#[no_mangle]
pub unsafe extern "C" fn sudo_relay_execution_review(
    input: *const u8,
    len: usize,
    output: *mut u8,
    capacity: usize,
) -> isize {
    if input.is_null() || output.is_null() || len == 0 || len > 4096 {
        return -1;
    }
    match std::panic::catch_unwind(|| dispatch(unsafe { std::slice::from_raw_parts(input, len) })) {
        Ok(Ok(bytes)) if bytes.len() <= capacity => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
            bytes.len() as isize
        }
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn host_pin_path_is_one_quoted_openssh_path() {
        assert_eq!(
            known_hosts_option(Path::new(
                "/Library/Application Support/sudo-relay/known_hosts"
            ))
            .unwrap(),
            "UserKnownHostsFile=\"/Library/Application Support/sudo-relay/known_hosts\""
        );
        for path in ["/bad\"path", "/bad\\path", "/bad\npath"] {
            assert!(known_hosts_option(Path::new(path)).is_err());
        }
    }

    fn fixture() -> (Enrollment, Envelope, Value, SigningKey) {
        let key = SigningKey::from_slice(&[39; 32]).unwrap();
        let enrollment = Enrollment {
            version: 1,
            purpose: "disposable-linux-execution-v1".into(),
            approver_uid: 501,
            machine_id: uuid::Uuid::new_v4().to_string(),
            machine_name: "Linux trial".into(),
            operating_system: "Debian 13".into(),
            account: "sponsor_a".into(),
            signing_key: format!(
                "p256-sha256:{}",
                hex::encode(key.verifying_key().to_sec1_point(false).as_bytes())
            ),
            signing_key_id: "native".into(),
            port: 2222,
            ssh_user: Some("approver".into()),
            known_hosts: "/protected/hosts".into(),
            identity: "/protected/identity".into(),
        };
        let spec = serde_json::from_value(
            json!({"command":{"kind":"argv","argv":["/usr/bin/id","-u"]},"timeout_secs":5}),
        )
        .unwrap();
        let envelope = Envelope::new(&enrollment.machine_id, spec, 100, 300).unwrap();
        let status = status(&envelope);
        (enrollment, envelope, status, key)
    }
    fn status(env: &Envelope) -> Value {
        let bytes = env.signing_payload().unwrap();
        json!({"id":env.id,"state":"pending","pending":{"envelope":env,"signing_payload":hex::encode(&bytes),"digest":hex::encode(Sha256::digest(&bytes))}})
    }
    fn operation(env: &Envelope, signature: String, share_output: bool) -> Operation {
        Operation::Approve {
            enrollment: "/unused".into(),
            id: env.id.clone(),
            signature,
            share_output,
        }
    }
    #[test]
    fn enrollment_rejects_receipt_purpose_account_and_unknown_fields() {
        let (enrollment, _, _, _) = fixture();
        enrollment.validate(501).unwrap();
        let mut preview: Enrollment =
            serde_json::from_value(serde_json::to_value(&enrollment).unwrap()).unwrap();
        preview.purpose = "linux-developer-preview-v1".into();
        preview.ssh_user = Some("sr-review-1234".into());
        preview.validate(501).unwrap();
        for user in [
            "root",
            "",
            "-oProxyCommand=bad",
            "name@otherhost",
            "name\nother",
        ] {
            preview.ssh_user = Some(user.into());
            assert!(preview.validate(501).is_err());
        }
        let mut vm: Enrollment =
            serde_json::from_value(serde_json::to_value(&enrollment).unwrap()).unwrap();
        vm.purpose = "disposable-linux-vm-execution-v1".into();
        vm.validate(501).unwrap();
        assert!(enrollment.validate(502).is_err());
        assert!(enrollment.validate(0).is_err());
        for (field, value) in [
            ("purpose", json!("receipt")),
            ("port", json!(0)),
            ("identity", json!("relative")),
            ("machine_name", json!("injected\nlabel")),
        ] {
            let mut data = serde_json::to_value(&enrollment).unwrap();
            data[field] = value;
            assert!(serde_json::from_value::<Enrollment>(data)
                .unwrap()
                .validate(501)
                .is_err());
        }
        let mut data = serde_json::to_value(&enrollment).unwrap();
        data["receipt_only"] = json!(true);
        assert!(serde_json::from_value::<Enrollment>(data).is_err());
    }
    #[test]
    fn frozen_review_rejects_receipts_expiry_other_target_and_other_command() {
        let (enrollment, env, mut status, _) = fixture();
        prepare(&enrollment, &env.id, &status, 101).unwrap();
        assert!(prepare(&enrollment, &env.id, &status, 400).is_err());
        assert!(prepare(&enrollment, "other", &status, 101).is_err());
        status["receipt_only"] = json!(true);
        assert!(prepare(&enrollment, &env.id, &status, 101).is_err());
        let mut changed = env.clone();
        changed.spec.command = Command::Argv {
            argv: vec!["/usr/bin/id".into(), "-un".into()],
        };
        assert!(prepare(&enrollment, &env.id, &self::status(&changed), 101).is_err());
        changed = env.clone();
        changed.machine_id = uuid::Uuid::new_v4().to_string();
        assert!(prepare(&enrollment, &env.id, &self::status(&changed), 101).is_err());
    }
    #[test]
    fn closing_remotely_cancelled_or_expired_review_never_submits_another_decision() {
        let (enrollment, env, _, _) = fixture();
        for state in ["cancelled", "expired"] {
            let mut reads = 0;
            let result = handle(
                Operation::Cancel {
                    enrollment: "/unused".into(),
                    id: env.id.clone(),
                },
                &enrollment,
                |request| {
                    assert!(matches!(request, Request::ExecutionStatus { .. }));
                    reads += 1;
                    Ok(json!({"id":env.id,"state":state,"pending":null}))
                },
                101,
            )
            .unwrap();
            assert_eq!(result, json!({"closed":true,"state":state}));
            assert_eq!(reads, 1);
            for operation in [
                Operation::Fetch {
                    enrollment: "/unused".into(),
                    id: env.id.clone(),
                },
                operation(&env, String::new(), false),
            ] {
                assert!(handle(
                    operation,
                    &enrollment,
                    |request| {
                        assert!(matches!(request, Request::ExecutionStatus { .. }));
                        Ok(json!({"id":env.id,"state":state}))
                    },
                    101
                )
                .is_err());
            }
        }
    }
    #[test]
    fn close_race_requires_confirmed_cancellation_or_expiry_without_retrying() {
        let (enrollment, env, pending, _) = fixture();
        for (after, accepted) in [
            (Some(json!({"id":env.id,"state":"cancelled"})), true),
            (Some(json!({"id":env.id,"state":"expired"})), true),
            (Some(pending.clone()), false),
            (Some(json!({"id":env.id,"state":"complete"})), false),
            (Some(json!({"id":"other","state":"cancelled"})), false),
            (
                Some(json!({"id":env.id,"state":"cancelled","receipt_only":true})),
                false,
            ),
            (None, false),
        ] {
            let mut reads = 0;
            let mut cancellations = 0;
            let result = handle(
                Operation::Cancel {
                    enrollment: "/unused".into(),
                    id: env.id.clone(),
                },
                &enrollment,
                |request| match request {
                    Request::ExecutionStatus { .. } => {
                        reads += 1;
                        if reads == 1 {
                            Ok(pending.clone())
                        } else {
                            after.clone().context("status connection lost")
                        }
                    }
                    Request::CancelExecution { .. } => {
                        cancellations += 1;
                        anyhow::bail!("cancel failed")
                    }
                    _ => panic!("close must not approve or execute"),
                },
                400,
            );
            assert_eq!(result.is_ok(), accepted, "{after:?}");
            assert_eq!(reads, 2);
            assert_eq!(cancellations, 1);
        }
    }
    #[test]
    fn only_exact_execution_signature_reaches_submission() {
        let (enrollment, env, status, key) = fixture();
        for (payload, share, accepted) in [
            (env.approval_payload(false).unwrap(), false, true),
            (env.approval_payload(true).unwrap(), true, true),
            (env.approval_payload(false).unwrap(), true, false),
            (env.receipt_approval_payload(false).unwrap(), false, false),
        ] {
            let proof: Signature = key.sign(&payload);
            let mut submissions = 0;
            let result = handle(
                operation(&env, hex::encode(proof.to_der()), share),
                &enrollment,
                |request| match request {
                    Request::ExecutionStatus { .. } => Ok(status.clone()),
                    Request::Approve { .. } => {
                        submissions += 1;
                        Ok(json!({"id":env.id,"state":"consumed"}))
                    }
                    _ => panic!("unexpected request"),
                },
                101,
            );
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(submissions, usize::from(accepted));
        }
    }
    #[test]
    fn pending_close_requires_a_matching_cancellation_acknowledgement() {
        let (enrollment, env, pending, _) = fixture();
        for (reply, accepted) in [
            (json!({"id":env.id,"state":"cancelled"}), true),
            (json!({"id":"other","state":"cancelled"}), false),
            (json!({"id":env.id,"state":"consumed"}), false),
        ] {
            let mut cancellations = 0;
            let result = handle(
                Operation::Cancel {
                    enrollment: "/unused".into(),
                    id: env.id.clone(),
                },
                &enrollment,
                |request| match request {
                    Request::ExecutionStatus { .. } => Ok(pending.clone()),
                    Request::CancelExecution { .. } => {
                        cancellations += 1;
                        Ok(reply.clone())
                    }
                    _ => panic!("unexpected mutation"),
                },
                101,
            );
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(cancellations, 1);
        }
        for status in [
            None,
            Some(json!({"id":"other","state":"cancelled"})),
            Some(json!({"id":env.id,"state":"cancelled","receipt_only":true})),
            Some(json!({"id":env.id,"state":"running"})),
            Some(json!({"id":env.id,"state":"consumed"})),
            Some(json!({"id":env.id,"state":"complete"})),
        ] {
            assert!(handle(
                Operation::Cancel {
                    enrollment: "/unused".into(),
                    id: env.id.clone()
                },
                &enrollment,
                |request| {
                    assert!(matches!(request, Request::ExecutionStatus { .. }));
                    status.clone().context("status unavailable")
                },
                101,
            )
            .is_err());
        }
    }
    #[test]
    fn missing_or_wrong_ack_never_retries() {
        let (enrollment, env, status, key) = fixture();
        let proof: Signature = key.sign(&env.approval_payload(false).unwrap());
        for acknowledgement in [
            None,
            Some(json!({"id":"other","state":"consumed"})),
            Some(json!({"id":env.id,"state":"pending"})),
        ] {
            let mut submissions = 0;
            let result = handle(
                operation(&env, hex::encode(proof.to_der()), false),
                &enrollment,
                |request| {
                    if matches!(request, Request::ExecutionStatus { .. }) {
                        return Ok(status.clone());
                    }
                    submissions += 1;
                    acknowledgement.clone().context("connection lost")
                },
                101,
            );
            assert!(result.is_err());
            assert_eq!(submissions, 1);
        }
    }
}
