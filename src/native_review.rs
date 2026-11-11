//! Native review and protected policy reading; never signs approvals.
use crate::protocol::{Envelope, MAX_REQUEST_BYTES};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
