//! Disposable Linux feasibility probe. Never install this PAM module on a real host.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::{
    ffi::{c_char, c_int, c_void, CStr},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    payload: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    domain: String,
    machine: String,
    sponsor: String,
    uid: u32,
    pid: u32,
    start: String,
    expires: u64,
    nonce: String,
    argv: Vec<String>,
}

fn private_read(path: &Path) -> Option<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 65_536 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 65_536).then_some(bytes)
}

unsafe fn pam_text(handle: *mut c_void, item: c_int) -> Option<String> {
    type GetItem = unsafe extern "C" fn(*const c_void, c_int, *mut *const c_void) -> c_int;
    let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"pam_get_item".as_ptr());
    if symbol.is_null() {
        return None;
    }
    let get_item: GetItem = std::mem::transmute(symbol);
    let mut value = std::ptr::null();
    if get_item(handle, item, &mut value) != 0 || value.is_null() {
        return None;
    }
    Some(CStr::from_ptr(value.cast()).to_str().ok()?.to_owned())
}

fn verified_grant(pid: u32) -> Option<Grant> {
    // The root-only grant directory and process binding are fixture assumptions, not a production protocol.
    let directory = Path::new("/lab/grants");
    let meta = fs::symlink_metadata(directory).ok()?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return None;
    }
    let ticket: Ticket =
        serde_json::from_slice(&private_read(&directory.join(format!("{pid}.json")))?).ok()?;
    let payload = hex::decode(ticket.payload).ok()?;
    let key: [u8; 32] = hex::decode(private_read(Path::new("/lab/public.hex"))?)
        .ok()?
        .try_into()
        .ok()?;
    VerifyingKey::from_bytes(&key)
        .ok()?
        .verify_strict(
            &payload,
            &Signature::from_slice(&hex::decode(ticket.signature).ok()?).ok()?,
        )
        .ok()?;
    let grant: Grant = serde_json::from_slice(&payload).ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if grant.domain != "sudo-relay/pam-prototype/v1"
        || grant.machine != fs::read_to_string("/lab/machine").ok()?
        || grant.pid != pid
        || grant.expires <= now
        || grant.expires > now.checked_add(300)?
        || grant.nonce.len() != 64
        || hex::decode(&grant.nonce).ok()?.len() != 32
        || grant.nonce != hex::encode(hex::decode(&grant.nonce).ok()?)
        || grant.uid == 0
    {
        return None;
    }
    Some(grant)
}

fn consume(nonce: &str, stage: &str) -> Option<()> {
    let directory = Path::new("/lab/grants");
    let receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(format!("{nonce}.{stage}")))
        .ok()?;
    receipt.sync_all().ok()?;
    fs::File::open(directory).ok()?.sync_all().ok()?;
    Some(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    sponsor: String,
    uid: u32,
    pid: u32,
    start: String,
    argv: Vec<String>,
}

/// Fixture controller gate, called as root before releasing its waiting sponsor process.
/// Expected fields come from the controller's own launch record, never from the ticket.
pub fn authorize_launch(expected: &str) -> Option<()> {
    if unsafe { libc::geteuid() } != 0 || expected.len() > 65_536 {
        return None;
    }
    let launch: Launch = serde_json::from_str(expected).ok()?;
    let grant = verified_grant(launch.pid)?;
    if grant.sponsor != launch.sponsor
        || grant.uid != launch.uid
        || grant.start != launch.start
        || grant.argv != launch.argv
        || !launch
            .argv
            .starts_with(&["/usr/bin/sudo", "-k", "-S", "-u", "root", "--"].map(String::from))
        || launch.argv.len() < 7
    {
        return None;
    }
    let stat = fs::read_to_string(format!("/proc/{}/stat", launch.pid)).ok()?;
    if stat.rsplit_once(") ")?.1.split_whitespace().nth(19)? != launch.start {
        return None;
    }
    let status = fs::read_to_string(format!("/proc/{}/status", launch.pid)).ok()?;
    let uids: Vec<u32> = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if uids != vec![launch.uid; 4] {
        return None;
    }
    // This receipt is mandatory even when sudo skips PAM. Never refund a released grant.
    consume(&grant.nonce, "released")
}

unsafe fn authenticate(handle: *mut c_void) -> Option<()> {
    let grant = verified_grant(std::process::id())?;
    if grant.sponsor != pam_text(handle, 2)? || grant.sponsor != pam_text(handle, 8)? {
        return None;
    }
    let name = std::ffi::CString::new(grant.sponsor).ok()?;
    let user = libc::getpwnam(name.as_ptr());
    if user.is_null() || (*user).pw_uid != grant.uid {
        return None;
    }
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let start = stat.rsplit_once(") ")?.1.split_whitespace().nth(19)?;
    if start != grant.start {
        return None;
    }
    let cmdline = fs::read("/proc/self/cmdline").ok()?;
    let actual: Vec<&[u8]> = cmdline
        .strip_suffix(&[0])?
        .split(|byte| *byte == 0)
        .collect();
    if actual.len() != grant.argv.len()
        || !actual
            .iter()
            .zip(&grant.argv)
            .all(|(a, b)| *a == b.as_bytes())
    {
        return None;
    }
    // PAM redemption is separate from the controller's pre-launch consumption.
    consume(&grant.nonce, "consumed")
}

/// # Safety
/// Called only by Linux PAM with its live handle; no Rust panic crosses the C boundary.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: *mut c_void,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    match std::panic::catch_unwind(|| authenticate(handle)) {
        Ok(Some(())) => 0,
        _ => 7,
    }
}

/// # Safety
/// PAM owns all arguments; this prototype establishes no additional credentials.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _: *mut c_void,
    _: c_int,
    _: c_int,
    _: *const *const c_char,
) -> c_int {
    0
}
