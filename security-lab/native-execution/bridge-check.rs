//! Headless container fixture for the exact native-app bridge; never signs.
use std::io::{Read, Write};
fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "linux") && std::path::Path::new("/.dockerenv").exists(),
        "container fixture only"
    );
    let mut input = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut input)?;
    let mut output = vec![0u8; 131072];
    let count = unsafe {
        sudo_relay::sudo_relay_execution_review(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    anyhow::ensure!(
        count > 0,
        "native execution bridge rejected request or acknowledgement unknown"
    );
    std::io::stdout().write_all(&output[..count as usize])?;
    Ok(())
}
