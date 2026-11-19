//! Display-only OS identity for the local receipt fixture; never runs an executable.
#[cfg(target_os = "macos")]
pub fn operating_system() -> String {
    let mut bytes = [0_u8; 128];
    let mut size = bytes.len();
    // Fixed sysctl name and bounded output buffer; the returned size is checked before reading.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 && size > 1 && size <= bytes.len() {
        if let Ok(version) = std::ffi::CStr::from_bytes_with_nul(&bytes[..size]) {
            let version = version.to_string_lossy();
            if version.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                return format!("macOS {version}");
            }
        }
    }
    "macOS (version unavailable)".into()
}

#[cfg(target_os = "linux")]
pub fn operating_system() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|release| {
            release.lines().find_map(|line| {
                let value = line.strip_prefix("PRETTY_NAME=")?.trim_matches('"');
                (!value.is_empty() && value.len() <= 120 && !value.chars().any(char::is_control))
                    .then(|| value.to_owned())
            })
        })
        .unwrap_or_else(|| "Linux (distribution unavailable)".into())
}
