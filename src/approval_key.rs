use anyhow::{ensure, Context, Result};
use ed25519_dalek::VerifyingKey;
use p256::ecdsa::signature::Verifier;

/// The administrator's stored key selects the algorithm, never an approval field.
pub enum ApprovalKey {
    Ed25519(VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl ApprovalKey {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if let Some(encoded) = value.strip_prefix("p256-sha256:") {
            ensure!(
                encoded.len() == 130,
                "expected an uncompressed 65-byte P-256 public key"
            );
            let bytes = hex::decode(encoded)?;
            ensure!(bytes[0] == 4, "expected uncompressed SEC1 public key");
            Ok(Self::P256(p256::ecdsa::VerifyingKey::from_sec1_bytes(
                &bytes,
            )?))
        } else {
            ensure!(value.len() == 64, "expected a 32-byte Ed25519 public key");
            let bytes: [u8; 32] = hex::decode(value)?.try_into().expect("length checked");
            Ok(Self::Ed25519(VerifyingKey::from_bytes(&bytes)?))
        }
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::Ed25519(key) => key
                .verify_strict(payload, &ed25519_dalek::Signature::from_slice(signature)?)
                .context("invalid approval signature"),
            Self::P256(key) => {
                ensure!(signature.len() <= 72, "P-256 signature exceeds DER limit");
                let signature = p256::ecdsa::Signature::from_der(signature)?;
                key.verify(payload, &signature)
                    .context("invalid approval signature")
            }
        }
    }
}
