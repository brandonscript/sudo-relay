//! Fixture only: does not execute commands or supply an installation/enrollment API.
use std::io::Read;
fn main() {
    let mut expected = String::new();
    if std::io::stdin()
        .take(65_537)
        .read_to_string(&mut expected)
        .is_err()
        || sudo_relay_pam_prototype::authorize_launch(&expected).is_none()
    {
        eprintln!("Approval gate denied launch");
        std::process::exit(1);
    }
}
