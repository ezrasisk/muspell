//! Cryptographic ownership validation.
//!
//! The KNS record includes an `ownership_proof`: an Ed25519 signature produced
//! by signing the canonical message `"muspell-ownership::<iroh_node_id>"` with
//! the same private key that controls the Iroh node.
//!
//! Validation pipeline:
//! 1. Decode the Iroh node ID from the KNS record (hex → Ed25519 public key).
//! 2. Re-construct the canonical message.
//! 3. Verify the signature.
//! 4. Confirm the decoded key matches the key the peer actually presented on
//!    the Iroh connection layer (prevents relay-based spoofing).

use ed25519_dalek::{Signature, VerifyingKey};
use tracing::{debug, instrument};

use crate::{
    error::{MuspellError, Result},
    kns::KnsRecord,
};

/// Canonical message prefix used when generating / verifying ownership proofs.
const PROOF_PREFIX: &str = "muspell-ownership::";

/// Stateless validator — all methods are pure functions of their arguments.
pub struct OwnershipValidator;

impl OwnershipValidator {
    // ── Public API ────────────────────────────────────────────────────────

    /// Full validation pipeline:
    ///
    /// 1. Confirm `presented_node_id` matches the ID stored in `record`.
    /// 2. Verify the `ownership_proof` signature.
    ///
    /// # Errors
    ///
    /// Returns [`MuspellError::NodeKeyMismatch`] or
    /// [`MuspellError::InvalidOwnershipProof`] on failure.
    #[instrument(skip(record), fields(name = %record.name))]
    pub fn validate(record: &KnsRecord, presented_node_id: &str) -> Result<()> {
        // Step 1: key identity check
        if !constant_time_eq(record.iroh_node_id.as_bytes(), presented_node_id.as_bytes()) {
            return Err(MuspellError::NodeKeyMismatch {
                kns_owner: record.iroh_node_id.clone(),
                presented: presented_node_id.to_string(),
            });
        }

        // Step 2: signature verification
        Self::verify_ownership_proof(
            &record.iroh_node_id,
            &record.ownership_proof,
        )?;

        debug!("ownership proof valid");
        Ok(())
    }

    /// Verify the ownership proof standalone (useful when updating a record).
    ///
    /// # Errors
    ///
    /// * [`MuspellError::NodeKeyMismatch`] – node ID is not valid hex / 32 bytes.
    /// * [`MuspellError::InvalidOwnershipProof`] – signature does not verify.
    pub fn verify_ownership_proof(node_id_hex: &str, proof_b64: &str) -> Result<()> {
        let verifying_key = Self::parse_verifying_key(node_id_hex)?;
        let signature    = Self::parse_signature(node_id_hex, proof_b64)?;
        let message      = Self::canonical_message(node_id_hex);

        verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .map_err(|_| MuspellError::InvalidOwnershipProof {
                node_id: node_id_hex.to_string(),
            })?;

        Ok(())
    }

    /// Build the canonical ownership proof message for `node_id_hex`.
    ///
    /// The string is deliberately human-readable so it can be verified out-of-band.
    #[must_use]
    pub fn canonical_message(node_id_hex: &str) -> String {
        format!("{PROOF_PREFIX}{node_id_hex}")
    }

    // ── Private helpers ───────────────────────────────────────────────────

    fn parse_verifying_key(hex: &str) -> Result<VerifyingKey> {
        let bytes = hex::decode(hex).map_err(|_| MuspellError::NodeKeyMismatch {
            kns_owner: hex.to_string(),
            presented: "(decode error)".to_string(),
        })?;

        if bytes.len() != 32 {
            return Err(MuspellError::NodeKeyMismatch {
                kns_owner: hex.to_string(),
                presented: format!("wrong key length: {} bytes", bytes.len()),
            });
        }

        let arr: [u8; 32] = bytes.try_into().expect("length checked above");
        VerifyingKey::from_bytes(&arr).map_err(MuspellError::Ed25519)
    }

    fn parse_signature(node_id: &str, proof_b64: &str) -> Result<Signature> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let bytes = STANDARD.decode(proof_b64).map_err(|_| {
            MuspellError::InvalidOwnershipProof {
                node_id: node_id.to_string(),
            }
        })?;

        Signature::from_slice(&bytes).map_err(MuspellError::Ed25519)
    }
}

/// Constant-time byte comparison to avoid timing oracles.
///
/// Uses a simple XOR fold rather than pulling in a dedicated crate.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn make_proof(key: &SigningKey, node_id_hex: &str) -> String {
        let msg = OwnershipValidator::canonical_message(node_id_hex);
        let sig = key.sign(msg.as_bytes());
        STANDARD.encode(sig.to_bytes())
    }

    #[test]
    fn valid_proof_passes() {
        let key       = SigningKey::generate(&mut OsRng);
        let node_id   = hex::encode(key.verifying_key().to_bytes());
        let proof     = make_proof(&key, &node_id);

        assert!(OwnershipValidator::verify_ownership_proof(&node_id, &proof).is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let key1      = SigningKey::generate(&mut OsRng);
        let key2      = SigningKey::generate(&mut OsRng);
        let node_id   = hex::encode(key1.verifying_key().to_bytes());
        let proof     = make_proof(&key2, &node_id); // signed with wrong key

        assert!(OwnershipValidator::verify_ownership_proof(&node_id, &proof).is_err());
    }

    #[test]
    fn key_mismatch_detected() {
        let key1    = SigningKey::generate(&mut OsRng);
        let key2    = SigningKey::generate(&mut OsRng);
        let id1     = hex::encode(key1.verifying_key().to_bytes());
        let id2     = hex::encode(key2.verifying_key().to_bytes());
        let proof   = make_proof(&key1, &id1);

        // Build a record whose iroh_node_id differs from the presented id
        let record = crate::kns::KnsRecord {
            name: "test.kas".to_string(),
            iroh_node_id: id1,
            relay_hints: vec![],
            ownership_proof: proof,
            block_height: 1,
        };

        let result = OwnershipValidator::validate(&record, &id2);
        assert!(matches!(result, Err(MuspellError::NodeKeyMismatch { .. })));
    }
}
