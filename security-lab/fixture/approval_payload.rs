// Fixture-only encoder; not installed with the broker or exposed through MCP.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 2, "expected request payload hex and sharing boolean");
    let payload = sudo_relay::protocol::approval_payload(
        &hex::decode(&args[0])?, args[1].parse::<bool>()?,
    )?;
    println!("{}", hex::encode(payload));
    Ok(())
}
