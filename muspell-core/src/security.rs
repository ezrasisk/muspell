//! Cryptographic ownership validation.
//!
//! The KNS record includes an `ownership_proof`: an Ed25519 signature produced
//! by signing the canonical message `"muspell-ownership::<iroh_node_id>"` with
//! the same private key that controls the Iroh node.
//!
//! Validation pipeline:
//! 1. Decode the Iroh node ID from the KNS record (hex → 32 bytes → Ed25519 pk).
//! 2. Re-construct the canonical message.
//! 3. Verify the signature.
//! 4. Confirm the decoded key matches the key the peer actually presented on
//!    the Iroh connection layer (prevents relay-based spoofing).

use base64::{engine::general_purpose::STANDARD, Engine};
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
        if !constant_time_eq(record.iroh_node_id.as_bytes(), presented_node_id.as_bytes()) {
            return Err(MuspellError::NodeKeyMismatch {
                kns_owner: record.iroh_node_id.clone(),
                presented: presented_node_id.to_string(),
            });
        }

        Self::verify_ownership_proof(&record.iroh_node_id, &record.ownership_proof)?;

        debug!("ownership proof valid");
        Ok(())
    }

    /// Verify an ownership proof standalone (useful when validating a fresh
    /// KNS record before registering it with the discovery provider).
    ///
    /// # Errors
    ///
    /// * [`MuspellError::NodeKeyMismatch`] – `node_id_hex` is not valid 32-byte hex.
    /// * [`MuspellError::InvalidOwnershipProof`] – signature does not verify.
    pub fn verify_ownership_proof(node_id_hex: &str, proof_b64: &str) -> Result<()> {
        let verifying_key = Self::parse_verifying_key(node_id_hex)?;
        let signature = Self::parse_signature(node_id_hex, proof_b64)?;
        let message = Self::canonical_message(node_id_hex);

        verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .map_err(|_| MuspellError::InvalidOwnershipProof {
                node_id: node_id_hex.to_string(),
            })?;

        Ok(())
    }

    /// Build the canonical ownership proof message for `node_id_hex`.
    ///
    /// The string is deliberately human-readable so it can be verified
    /// out-of-band with standard ed25519 tooling.
    #[must_use]
    pub fn canonical_message(node_id_hex: &str) -> String {
        format!("{PROOF_PREFIX}{node_id_hex}")
    }

    // ── Private helpers ───────────────────────────────────────────────────

    fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey> {
        let bytes = hex::decode(hex_str).map_err(|_| MuspellError::NodeKeyMismatch {
            kns_owner: hex_str.to_string(),
            presented: "(hex decode error)".to_string(),
        })?;

        let arr: [u8; 32] = bytes.try_into().map_err(|_| MuspellError::NodeKeyMismatch {
            kns_owner: hex_str.to_string(),
            presented: "wrong key length (expected 32 bytes)".to_string(),
        })?;

        VerifyingKey::from_bytes(&arr).map_err(MuspellError::Ed25519)
    }

    fn parse_signature(node_id: &str, proof_b64: &str) -> Result<Signature> {
        let bytes = STANDARD.decode(proof_b64).map_err(|_| {
            MuspellError::InvalidOwnershipProof {
                node_id: node_id.to_string(),
            }
        })?;

        // Signature::from_slice expects exactly 64 bytes.
        Signature::from_slice(&bytes).map_err(MuspellError::Ed25519)
    }
}

/// Constant-time byte comparison to avoid timing oracles on key material.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR-fold: result is zero iff all bytes matched.
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_proof(signing_key: &SigningKey, node_id_hex: &str) -> String {
        let msg = OwnershipValidator::canonical_message(node_id_hex);
        let sig = signing_key.sign(msg.as_bytes());
        STANDARD.encode(sig.to_bytes())
    }

    #[test]
    fn valid_proof_passes() {
        let key = SigningKey::generate(&mut OsRng);
        let node_id = hex::encode(key.verifying_key().to_bytes());
        let proof = make_proof(&key, &node_id);

        assert!(OwnershipValidator::verify_ownership_proof(&node_id, &proof).is_ok());
    }

    #[test]
    fn wrong_signing_key_fails() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let node_id = hex::encode(key1.verifying_key().to_bytes());
        // Sign with key2 but claim to be key1 — should fail
        let proof = make_proof(&key2, &node_id);

        assert!(OwnershipValidator::verify_ownership_proof(&node_id, &proof).is_err());
    }

    #[test]
    fn key_mismatch_detected() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let id1 = hex::encode(key1.verifying_key().to_bytes());
        let id2 = hex::encode(key2.verifying_key().to_bytes());
        let proof = make_proof(&key1, &id1);

        let record = crate::kns::KnsRecord {
            name: "test.kas".to_string(),
            iroh_node_id: id1,
            relay_hints: vec![],
            ownership_proof: proof,
            block_height: 1,
        };

        // Present id2 against a record that expects id1.
        let result = OwnershipValidator::validate(&record, &id2);
        assert!(matches!(result, Err(MuspellError::NodeKeyMismatch { .. })));
    }

    #[test]
    fn invalid_hex_returns_error() {
        let result = OwnershipValidator::verify_ownership_proof("not-hex!!", "c2ln");
        assert!(matches!(result, Err(MuspellError::NodeKeyMismatch { .. })));
    }

    #[test]
    fn invalid_base64_proof_returns_error() {
        let key = SigningKey::generate(&mut OsRng);
        let node_id = hex::encode(key.verifying_key().to_bytes());
        // Garbage base64
        let result = OwnershipValidator::verify_ownership_proof(&node_id, "!!!notb64!!!");
        assert!(matches!(
            result,
            Err(MuspellError::InvalidOwnershipProof { .. })
        ));
    }
}
