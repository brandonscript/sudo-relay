//! Fixture only: does not execute commands or supply an installation/enrollment API.
use std::io::Read;
fn main() {
    let mut expected = String::new();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let authorize = |expected: &str| match arguments.as_slice() {
        [] => sudo_relay_pam_prototype::authorize_launch(expected),
        [root] => {
            sudo_relay_pam_prototype::authorize_launch_at(std::path::Path::new(root), expected)
        }
        _ => None,
    };
    if std::io::stdin()
        .take(65_537)
        .read_to_string(&mut expected)
        .is_err()
        || authorize(&expected).is_none()
    {
        eprintln!("Approval gate denied launch");
        std::process::exit(1);
    }
}
