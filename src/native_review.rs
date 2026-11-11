//! Native review and protected policy reading; never signs approvals.
use crate::protocol::{Envelope, MAX_REQUEST_BYTES};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewReference {
    enrollment: std::path::PathBuf,
    id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewEnrollment {
    version: u8,
    receipt_only: bool,
    machine_id: String,
    socket: std::path::PathBuf,
    approver_uid: u32,
    signing_key: String,
    signing_key_id: String,
    machine_name: String,
    operating_system: String,
    account: String,
}
impl ReviewEnrollment {
    fn validate(&self, uid: u32) -> Result<()> {
        ensure!(
            self.version == 1 && self.receipt_only,
            "unsupported review enrollment"
        );
        ensure!(
            self.approver_uid != 0 && self.approver_uid == uid,
            "wrong approving account"
        );
        ensure!(
            self.socket.is_absolute() && uuid::Uuid::parse_str(&self.machine_id).is_ok(),
            "invalid enrolled target"
        );
        ensure!(
            matches!(
                crate::approval_key::ApprovalKey::parse(&self.signing_key)?,
                crate::approval_key::ApprovalKey::P256(_)
            ),
            "native receipt enrollment requires P-256"
        );
        crate::broker::validate_key_id(&self.signing_key_id)?;
        for label in [&self.machine_name, &self.operating_system, &self.account] {
            ensure!(
                !label.is_empty()
                    && label.len() <= 100
                    && label.bytes().all(|b| (32..=126).contains(&b)),
                "invalid enrolled display label"
            );
        }
        Ok(())
    }
}

fn load_enrollment(reference: &ReviewReference) -> Result<ReviewEnrollment> {
    ensure!(
        reference.enrollment.is_absolute()
            && !reference.id.is_empty()
            && reference.id.len() <= 128
            && reference
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid review reference"
    );
    let enrollment: ReviewEnrollment = serde_json::from_slice(
        &crate::broker::read_protected_file(&reference.enrollment, 4096)?,
    )?;
    enrollment.validate(unsafe { libc::geteuid() })?;
    Ok(enrollment)
}

fn fetch_review(input: &[u8]) -> Result<Vec<u8>> {
    let reference: ReviewReference = serde_json::from_slice(input)?;
    let enrollment = load_enrollment(&reference)?;
    let status = crate::transport::call_protected(
        &enrollment.socket,
        &crate::protocol::Request::ExecutionStatus {
            id: reference.id.clone(),
        },
    )?;
    prepare_fetched_review(&enrollment, &reference.id, &status, crate::broker::now())
}

fn prepare_fetched_review(
    enrollment: &ReviewEnrollment,
    id: &str,
    status: &serde_json::Value,
    now: u64,
) -> Result<Vec<u8>> {
    ensure!(
        status["receipt_only"] == true && status["id"] == id && status["state"] == "pending",
        "review is not a pending receipt-only request"
    );
    let pending = &status["pending"];
    ensure!(pending["envelope"]["id"] == id, "wrong review reference");
    let bytes = serde_json::to_vec(pending)?;
    let mut review: serde_json::Value =
        serde_json::from_slice(&prepare(&bytes, &enrollment.machine_id, now)?)?;
    let envelope: Envelope = serde_json::from_value(review["envelope"].clone())?;
    review["approval_shared"] = hex::encode(envelope.receipt_approval_payload(true)?).into();
    review["approval_withheld"] = hex::encode(envelope.receipt_approval_payload(false)?).into();
    Ok(serde_json::to_vec(
        &serde_json::json!({"enrollment": enrollment, "review": review}),
    )?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSubmission {
    enrollment: std::path::PathBuf,
    id: String,
    signature: String,
    share_output: bool,
}

fn submit_receipt(input: &[u8]) -> Result<()> {
    let submission: ReceiptSubmission = serde_json::from_slice(input)?;
    let reference = ReviewReference {
        enrollment: submission.enrollment,
        id: submission.id,
    };
    let enrollment = load_enrollment(&reference)?;
    submit_enrolled(
        &enrollment,
        &reference.id,
        &submission.signature,
        submission.share_output,
        |request| crate::transport::call_protected(&enrollment.socket, &request),
    )
}

fn submit_enrolled(
    enrollment: &ReviewEnrollment,
    id: &str,
    signature: &str,
    share_output: bool,
    mut call: impl FnMut(crate::protocol::Request) -> Result<serde_json::Value>,
) -> Result<()> {
    ensure!(signature.len() <= 144, "signature too large");
    let proof = hex::decode(signature)?;
    let status = call(crate::protocol::Request::ExecutionStatus { id: id.into() })?;
    let prepared: serde_json::Value = serde_json::from_slice(&prepare_fetched_review(
        enrollment,
        id,
        &status,
        crate::broker::now(),
    )?)?;
    let envelope: Envelope = serde_json::from_value(prepared["review"]["envelope"].clone())?;
    crate::approval_key::ApprovalKey::parse(&enrollment.signing_key)?
        .verify(&envelope.receipt_approval_payload(share_output)?, &proof)?;
    let result = call(crate::protocol::Request::ApproveReceipt {
        id: id.into(),
        key_id: enrollment.signing_key_id.clone(),
        number: envelope.number,
        signature: signature.into(),
        share_output,
    })?;
    ensure!(
        result["receipt_only"] == true && result["id"] == id && result["state"] == "consumed",
        "receipt acknowledgement not verified"
    );
    Ok(())
}

/// Submit a signed receipt through protected enrollment. Never signs or retries.
/// Returns 1 only for a verified consumption acknowledgement; -1 otherwise.
/// A -1 may mean the reply was lost after consumption: never automatically retry.
///
/// # Safety
/// Input must reference input_len readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sudo_relay_submit_receipt(input: *const u8, input_len: usize) -> i32 {
    if input.is_null() || input_len == 0 || input_len > 4096 {
        return -1;
    }
    match std::panic::catch_unwind(|| {
        submit_receipt(unsafe { std::slice::from_raw_parts(input, input_len) })
    }) {
        Ok(Ok(())) => 1,
        _ => -1,
    }
}

/// Retrieve and validate a pending request from a root-authenticated local socket.
/// Root-owned enrollment supplies socket, machine pin, display labels and allowed approver UID.
/// Returns byte count, -1 on failure, -2 for insufficient capacity; errors write nothing.
/// This only fetches status: it cannot submit approval or dispatch a command.
///
/// # Safety
/// Input must reference input_len readable bytes; output must reference capacity writable
/// bytes disjoint from input.
#[no_mangle]
pub unsafe extern "C" fn sudo_relay_fetch_review(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    capacity: usize,
) -> isize {
    if input.is_null() || output.is_null() || input_len == 0 || input_len > 4096 {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        fetch_review(unsafe { std::slice::from_raw_parts(input, input_len) })
    });
    match result {
        Ok(Ok(bytes)) if bytes.len() <= capacity => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
            bytes.len() as isize
        }
        Ok(Ok(_)) => -2,
        _ => -1,
    }
}

/// Read at most 4096 bytes from a root-protected policy file.
/// Returns byte count, -1 on invalid/unprotected input, -2 for insufficient capacity.
///
/// # Safety
/// Path must reference path_len readable bytes; output must reference capacity writable
/// bytes disjoint from path. Errors leave output unchanged.
#[no_mangle]
pub unsafe extern "C" fn sudo_relay_read_peer_policy(
    path: *const u8,
    path_len: usize,
    output: *mut u8,
    capacity: usize,
) -> isize {
    if path.is_null() || output.is_null() || path_len == 0 || path_len > 4096 {
        return -1;
    }
    let result = std::panic::catch_unwind(|| {
        let bytes = unsafe { std::slice::from_raw_parts(path, path_len) };
        let path = std::str::from_utf8(bytes)?;
        crate::broker::read_protected_file(std::path::Path::new(path), 4096)
    });
    match result {
        Ok(Ok(bytes)) if bytes.len() <= capacity => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
            bytes.len() as isize
        }
        Ok(Ok(_)) => -2,
        _ => -1,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    envelope: Envelope,
    signing_payload: String,
    digest: String,
}

#[derive(Serialize)]
struct Review {
    envelope: Envelope,
    approval_shared: String,
    approval_withheld: String,
}

fn prepare(input: &[u8], machine: &str, now: u64) -> Result<Vec<u8>> {
    ensure!(input.len() <= MAX_REQUEST_BYTES, "review too large");
    ensure!(
        !machine.is_empty() && machine.len() <= 256,
        "invalid paired machine"
    );
    let pending: Pending = serde_json::from_slice(input)?;
    let env = pending.envelope;
    ensure!(
        !env.id.is_empty()
            && env.id.len() <= 128
            && env
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && !env.nonce.is_empty()
            && env.nonce.len() <= 128
            && env.nonce.len().is_multiple_of(2)
            && env.nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid request identity"
    );
    ensure!(
        env.version == 2 && env.machine_id == machine,
        "wrong protocol or machine"
    );
    ensure!(
        env.created_at <= now && now < env.expires_at,
        "review outside validity window"
    );
    ensure!(
        env.expires_at - env.created_at <= 86400,
        "invalid expiry window"
    );
    ensure!(
        env.number.len() == 2
            && env.number.as_bytes()[0].is_ascii_digit()
            && env.number.as_bytes()[0] != b'0'
            && env.number.as_bytes()[1].is_ascii_digit(),
        "invalid number"
    );
    env.spec.validate()?;
    let bytes = env.signing_payload()?;
    ensure!(
        pending.signing_payload == hex::encode(&bytes),
        "display and payload differ"
    );
    ensure!(
        pending.digest == hex::encode(Sha256::digest(&bytes)),
        "digest mismatch"
    );
    serde_json::to_vec(&Review {
        approval_shared: hex::encode(env.approval_payload(true)?),
        approval_withheld: hex::encode(env.approval_payload(false)?),
        envelope: env,
    })
    .map_err(Into::into)
}

/// Return the JSON byte count, -1 for invalid input, or -2 for insufficient output space.
/// No output bytes are written on error. The caller must authenticate the source separately.
///
/// # Safety
/// Input/machine pointers must reference readable regions of their declared lengths;
/// output must reference a writable region of capacity bytes, disjoint from both inputs.
#[no_mangle]
pub unsafe extern "C" fn sudo_relay_prepare_review(
    input: *const u8,
    input_len: usize,
    machine: *const u8,
    machine_len: usize,
    now: u64,
    output: *mut u8,
    capacity: usize,
) -> isize {
    if input.is_null()
        || machine.is_null()
        || output.is_null()
        || input_len > MAX_REQUEST_BYTES
        || machine_len > 256
    {
        return -1;
    }
    // Keep Rust unwinding out of the foreign caller; pointer validity is the C caller's contract.
    let result = std::panic::catch_unwind(|| {
        let input = unsafe { std::slice::from_raw_parts(input, input_len) };
        let machine = unsafe { std::slice::from_raw_parts(machine, machine_len) };
        let machine = std::str::from_utf8(machine)?;
        prepare(input, machine, now)
    });
    match result {
        Ok(Ok(bytes)) if bytes.len() <= capacity => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
            bytes.len() as isize
        }
        Ok(Ok(_)) => -2,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture_key() -> String {
        let key = p256::ecdsa::SigningKey::from_slice(&[27; 32]).unwrap();
        format!(
            "p256-sha256:{}",
            hex::encode(key.verifying_key().to_sec1_point(false).as_bytes())
        )
    }

    #[test]
    fn native_enrollment_binds_account_target_labels_and_receipt_mode() {
        let original = json!({"version":1,"receipt_only":true,"socket":"/run/receipt.sock",
            "machine_id":"00000000-0000-4000-8000-000000000001","approver_uid":10002,
            "signing_key":fixture_key(),"signing_key_id":"native","machine_name":"test-host","operating_system":"macOS test","account":"test-user"});
        let enrollment: ReviewEnrollment = serde_json::from_value(original.clone()).unwrap();
        enrollment.validate(10002).unwrap();
        assert!(enrollment.validate(10001).is_err());
        for (field, value) in [
            ("signing_key_id", json!("../injected")),
            ("signing_key_id", json!("")),
            ("signing_key", json!("p256-sha256:00")),
            (
                "signing_key",
                json!(format!("p256-sha256:04{}", "00".repeat(64))),
            ),
            ("signing_key", json!("00".repeat(32))),
            ("version", json!(2)),
            ("receipt_only", json!(false)),
            ("approver_uid", json!(0)),
            ("socket", json!("relative.sock")),
            ("machine_id", json!("invalid")),
            ("machine_name", json!("")),
            ("operating_system", json!("line\nbreak")),
            ("account", json!("a".repeat(101))),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<ReviewEnrollment>(changed)
                .unwrap()
                .validate(10002)
                .is_err());
        }
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("signing_key");
        assert!(serde_json::from_value::<ReviewEnrollment>(missing).is_err());
        let mut unknown = original;
        unknown["allow_fallback"] = json!(true);
        assert!(serde_json::from_value::<ReviewEnrollment>(unknown).is_err());
    }

    #[test]
    fn enrolled_review_requires_receipt_only_server_response() {
        let mut envelope: Envelope = serde_json::from_value(fixture()["envelope"].clone()).unwrap();
        envelope.machine_id = "00000000-0000-4000-8000-000000000001".into();
        let enrollment = ReviewEnrollment {
            version: 1,
            receipt_only: true,
            machine_id: envelope.machine_id.clone(),
            socket: "/run/test.sock".into(),
            approver_uid: 10002,
            signing_key: fixture_key(),
            signing_key_id: "native".into(),
            machine_name: "test-host".into(),
            operating_system: "test OS".into(),
            account: "test-user".into(),
        };
        let original = json!({"id":envelope.id,"state":"pending","pending":envelope.view().unwrap(),"receipt_only":true});
        let prepared: Value = serde_json::from_slice(
            &prepare_fetched_review(&enrollment, &envelope.id, &original, 1700000001).unwrap(),
        )
        .unwrap();
        for (field, share) in [("approval_shared", true), ("approval_withheld", false)] {
            assert_eq!(
                prepared["review"][field],
                hex::encode(envelope.receipt_approval_payload(share).unwrap())
            );
            assert_ne!(
                prepared["review"][field],
                hex::encode(envelope.approval_payload(share).unwrap())
            );
        }
        for value in [json!(false), json!(null), json!(1), json!("true")] {
            let mut changed = original.clone();
            changed["receipt_only"] = value;
            assert!(
                prepare_fetched_review(&enrollment, &envelope.id, &changed, 1700000001).is_err()
            );
        }
        let mut missing = original;
        missing.as_object_mut().unwrap().remove("receipt_only");
        assert!(prepare_fetched_review(&enrollment, &envelope.id, &missing, 1700000001).is_err());
    }

    #[test]
    #[cfg(feature = "native-receipt-lab")]
    fn native_submission_never_retries_lost_or_invalid_acknowledgements() {
        use crate::{
            broker::{Broker, Config},
            protocol::{PendingView, Request},
        };
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use std::{fs, os::unix::fs::PermissionsExt};
        for fault in [
            "before-consumption",
            "after-consumption",
            "wrong-id",
            "wrong-mode",
            "success",
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(dir.path().join("keys")).unwrap();
            let key = SigningKey::from_slice(&[27; 32]).unwrap();
            let path = dir.path().join("keys/native.pub");
            fs::write(&path, fixture_key()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            let uid = unsafe { libc::geteuid() };
            let enrollment = ReviewEnrollment {
                version: 1,
                receipt_only: true,
                machine_id: uuid::Uuid::new_v4().to_string(),
                socket: dir.path().join("run/unused.sock"),
                approver_uid: uid,
                signing_key: fixture_key(),
                signing_key_id: "native".into(),
                machine_name: "test".into(),
                operating_system: "test OS".into(),
                account: "test-user".into(),
            };
            enrollment.validate(uid).unwrap();
            let mut broker = Broker::open(
                Config {
                    machine_id: enrollment.machine_id.clone(),
                    agent_uid: uid,
                    approver_uid: uid,
                    socket_gid: unsafe { libc::getegid() },
                    state_dir: dir.path().into(),
                    socket: enrollment.socket.clone(),
                    approval_ttl_secs: 300,
                    max_execution_secs: 300,
                },
                true,
            )
            .unwrap();
            let spec = serde_json::from_value(fixture()["envelope"]["spec"].clone()).unwrap();
            let (reply, job) = broker
                .handle_current(Request::RequestExecution { spec }, uid)
                .unwrap();
            assert!(job.is_none());
            let pending: PendingView = serde_json::from_value(reply.value().unwrap()).unwrap();
            let id = &pending.envelope.id;
            let proof: Signature =
                key.sign(&pending.envelope.receipt_approval_payload(false).unwrap());
            let signature = hex::encode(proof.to_der());
            let mut calls = Vec::new();
            let result = submit_enrolled(&enrollment, id, &signature, false, |request| {
                let approving = matches!(request, Request::ApproveReceipt { .. });
                calls.push(approving);
                if approving && fault == "before-consumption" {
                    anyhow::bail!("connection lost before delivery");
                }
                let (reply, job) = if approving {
                    broker.handle_receipt_current(request, uid)?
                } else {
                    broker.handle_current(request, uid)?
                };
                assert!(job.is_none(), "receipt path returned an execution job");
                if approving && fault == "after-consumption" {
                    anyhow::bail!("reply lost after commit");
                }
                let mut value = reply.value()?;
                value["receipt_only"] = true.into();
                if approving && fault == "wrong-id" {
                    value["id"] = "different-request".into();
                }
                if approving && fault == "wrong-mode" {
                    value["receipt_only"] = false.into();
                }
                Ok(value)
            });
            assert_eq!(result.is_ok(), fault == "success", "{fault}");
            assert_eq!(calls, [false, true], "automatic retry after {fault}");
            let status = broker
                .handle_current(Request::ExecutionStatus { id: id.clone() }, uid)
                .unwrap()
                .0
                .value()
                .unwrap();
            let consumed = fault != "before-consumption";
            assert_eq!(
                status["state"],
                if consumed { "consumed" } else { "pending" }
            );
            let db = rusqlite::Connection::open_with_flags(
                dir.path().join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM audit WHERE event='consumed'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, i64::from(consumed));
            if consumed {
                let mut followups = 0;
                assert!(
                    submit_enrolled(&enrollment, id, &signature, false, |request| {
                        followups += 1;
                        assert!(matches!(request, Request::ExecutionStatus { .. }));
                        let mut value = broker.handle_current(request, uid)?.0.value()?;
                        value["receipt_only"] = true.into();
                        Ok(value)
                    })
                    .is_err()
                );
                assert_eq!(followups, 1);
            }
        }
    }

    #[test]
    fn native_submission_rejects_invalid_input_without_fallback() {
        for input in [b"null".as_slice(),
            br#"{"enrollment":"relative","id":"request","signature":"00","share_output":false}"#,
            br#"{"enrollment":"/missing","id":"request","signature":"not-hex","share_output":false}"#,
            br#"{"enrollment":"/missing","id":"request","signature":"00","share_output":false,"command":"injected"}"#,
        ] {
            assert_eq!(unsafe { sudo_relay_submit_receipt(input.as_ptr(), input.len()) }, -1);
        }
        assert_eq!(
            unsafe { sudo_relay_submit_receipt(std::ptr::null(), 1) },
            -1
        );
        assert_eq!(
            unsafe { sudo_relay_submit_receipt(b"x".as_ptr(), 4097) },
            -1
        );
    }

    #[test]
    fn native_fetch_rejects_invalid_references_without_output() {
        for input in [
            b"null".as_slice(),
            br#"{"enrollment":"relative","id":"request"}"#,
            br#"{"enrollment":"/missing.json","id":""}"#,
            br#"{"enrollment":"/missing.json","id":"request","command":"injected"}"#,
        ] {
            let mut output = [0xaa; 32];
            assert_eq!(
                unsafe {
                    sudo_relay_fetch_review(
                        input.as_ptr(),
                        input.len(),
                        output.as_mut_ptr(),
                        output.len(),
                    )
                },
                -1
            );
            assert_eq!(output, [0xaa; 32]);
        }
        let mut output = [0xaa; 32];
        assert_eq!(
            unsafe {
                sudo_relay_fetch_review(std::ptr::null(), 1, output.as_mut_ptr(), output.len())
            },
            -1
        );
        assert_eq!(output, [0xaa; 32]);
    }

    #[test]
    fn native_policy_errors_leave_output_untouched() {
        let mut output = [0xaa; 32];
        for path in [
            b"".as_slice(),
            b"relative/policy",
            b"/missing-policy\0",
            &[0xff],
        ] {
            let result = unsafe {
                sudo_relay_read_peer_policy(
                    path.as_ptr(),
                    path.len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            };
            assert_eq!(result, -1);
            assert_eq!(output, [0xaa; 32]);
        }
        assert_eq!(
            unsafe {
                sudo_relay_read_peer_policy(std::ptr::null(), 1, output.as_mut_ptr(), output.len())
            },
            -1
        );
        assert_eq!(output, [0xaa; 32]);
    }

    fn fixture() -> Value {
        let mut value: Value =
            serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .retain(|key, _| matches!(key.as_str(), "envelope" | "signing_payload" | "digest"));
        value
    }

    #[test]
    fn native_review_preserves_model_and_both_production_decisions() {
        let input = fixture();
        let output: Value = serde_json::from_slice(
            &prepare(
                &serde_json::to_vec(&input).unwrap(),
                "fixture-machine",
                1700000001,
            )
            .unwrap(),
        )
        .unwrap();
        let vector: Value = serde_json::from_str(include_str!("../ui/test/fixture.json")).unwrap();
        assert_eq!(output["envelope"], input["envelope"]);
        assert_eq!(output["approval_shared"], vector["approval_payload_shared"]);
        assert_eq!(
            output["approval_withheld"],
            vector["approval_payload_withheld"]
        );
        for (field, replacement) in [
            ("digest", json!("00")),
            ("signing_payload", json!("00")),
            ("extra", json!(true)),
        ] {
            let mut changed = fixture();
            changed[field] = replacement;
            assert!(prepare(
                &serde_json::to_vec(&changed).unwrap(),
                "fixture-machine",
                1700000001
            )
            .is_err());
        }
        for time in [1699999999, 1700000300] {
            assert!(prepare(
                &serde_json::to_vec(&input).unwrap(),
                "fixture-machine",
                time
            )
            .is_err());
        }
        assert!(prepare(
            &serde_json::to_vec(&input).unwrap(),
            "other-machine",
            1700000001
        )
        .is_err());
        let mut changed = fixture();
        changed["envelope"]["spec"]["command"]["argv"][1] = json!("different");
        assert!(prepare(
            &serde_json::to_vec(&changed).unwrap(),
            "fixture-machine",
            1700000001
        )
        .is_err());
    }

    #[test]
    fn bridge_errors_leave_caller_buffer_untouched() {
        let input = serde_json::to_vec(&fixture()).unwrap();
        let machine = b"fixture-machine";
        let mut output = [0xaa; 8];
        unsafe {
            assert_eq!(
                sudo_relay_prepare_review(
                    input.as_ptr(),
                    input.len(),
                    machine.as_ptr(),
                    machine.len(),
                    1700000001,
                    output.as_mut_ptr(),
                    output.len()
                ),
                -2
            );
            assert_eq!(
                sudo_relay_prepare_review(
                    std::ptr::null(),
                    0,
                    machine.as_ptr(),
                    machine.len(),
                    1700000001,
                    output.as_mut_ptr(),
                    output.len()
                ),
                -1
            );
            assert_eq!(
                sudo_relay_prepare_review(
                    input.as_ptr(),
                    MAX_REQUEST_BYTES + 1,
                    machine.as_ptr(),
                    machine.len(),
                    1700000001,
                    output.as_mut_ptr(),
                    output.len()
                ),
                -1
            );
        }
        assert_eq!(output, [0xaa; 8]);
    }

    #[test]
    fn native_review_rejects_self_consistent_but_invalid_requests() {
        let fixture: Pending = serde_json::from_value(fixture()).unwrap();
        let original = fixture.envelope;
        let mut invalid = Vec::new();
        let mut changed = original.clone();
        changed.version = 1;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.number = "01".into();
        invalid.push(changed);
        let mut changed = original.clone();
        changed.id = "request\nreplacement".into();
        invalid.push(changed);
        let mut changed = original.clone();
        changed.nonce = "not-hex".into();
        invalid.push(changed);
        let mut changed = original.clone();
        changed.expires_at = changed.created_at + 86401;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.spec.timeout_secs = 0;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.spec.reason = "hidden\u{202e}text".into();
        invalid.push(changed);
        let mut changed = original;
        changed
            .spec
            .env
            .insert("LD_PRELOAD".into(), "/tmp/library".into());
        invalid.push(changed);
        for envelope in invalid {
            let bytes = serde_json::to_vec(&envelope.view().unwrap()).unwrap();
            assert!(prepare(&bytes, "fixture-machine", 1700000001).is_err());
        }
    }
}
