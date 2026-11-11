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

fn fetch_review(input: &[u8]) -> Result<Vec<u8>> {
    let reference: ReviewReference = serde_json::from_slice(input)?;
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
            "signing_key":fixture_key(),"machine_name":"test-host","operating_system":"macOS test","account":"test-user"});
        let enrollment: ReviewEnrollment = serde_json::from_value(original.clone()).unwrap();
        enrollment.validate(10002).unwrap();
        assert!(enrollment.validate(10001).is_err());
        for (field, value) in [
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
