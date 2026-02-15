//! Signing: presignature generation and online signing.
//!
//! Two-phase approach for minimum latency:
//! 1. Presign (background): 3 MPC rounds between t parties → presignature
//! 2. Sign (online): combine presignature + message hash → ECDSA signature
//!
//! SECURITY: Never reuse a presignature for two different messages!

use rand_core::OsRng;

use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId, PartialSignature};

use crate::error::MpcError;

// Re-export types callers need
pub use cggmp21::Presignature;
pub use cggmp21::Signature as CggmpSignature;

/// ECDSA signature with recovery id for Ethereum.
#[derive(Debug, Clone)]
pub struct EthSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl EthSignature {
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_rsv()))
    }
}

/// Pool of ready-to-use presignatures for low-latency signing.
pub struct PresignaturePool {
    pool: Vec<cggmp21::Presignature<Secp256k1>>,
    target_size: usize,
    refill_threshold: usize,
}

impl PresignaturePool {
    pub fn new(target_size: usize, refill_threshold: usize) -> Self {
        Self {
            pool: Vec::with_capacity(target_size),
            target_size,
            refill_threshold,
        }
    }

    pub fn take(&mut self) -> Option<cggmp21::Presignature<Secp256k1>> {
        self.pool.pop()
    }

    pub fn available(&self) -> usize {
        self.pool.len()
    }

    pub fn needs_refill(&self) -> bool {
        self.pool.len() < self.refill_threshold
    }

    pub fn refill_count(&self) -> usize {
        self.target_size.saturating_sub(self.pool.len())
    }

    pub fn add(&mut self, presig: cggmp21::Presignature<Secp256k1>) {
        self.pool.push(presig);
    }
}

/// Generate a presignature via MPC between t parties.
pub async fn generate_presignature<D>(
    eid: ExecutionId<'_>,
    party_index_in_signing: u16,
    parties_indexes_at_keygen: &[u16],
    key_share: &cggmp21::KeyShare<Secp256k1>,
    delivery: D,
) -> Result<cggmp21::Presignature<Secp256k1>, MpcError>
where
    D: cggmp21::round_based::Delivery<
        cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>,
    >,
{
    tracing::info!(
        party_index_in_signing,
        ?parties_indexes_at_keygen,
        "starting presignature generation"
    );

    let party = cggmp21::round_based::MpcParty::connected(delivery);

    let presig = cggmp21::signing(eid, party_index_in_signing, parties_indexes_at_keygen, key_share)
        .generate_presignature(&mut OsRng, party)
        .await
        .map_err(|e| MpcError::Presign(format!("{e:?}")))?;

    tracing::info!("presignature generation complete");
    Ok(presig)
}

/// Issue a partial signature from a presignature (local, no network).
pub fn issue_partial_signature(
    presig: cggmp21::Presignature<Secp256k1>,
    message_hash: &[u8; 32],
) -> PartialSignature<Secp256k1> {
    let data = DataToSign::from_digest(sha2::Sha256::new_with_prefix(message_hash));
    presig.issue_partial_signature(data)
}

/// Combine partial signatures into a complete ECDSA signature.
pub fn combine_partial_signatures(
    partials: &[PartialSignature<Secp256k1>],
) -> Result<CggmpSignature<Secp256k1>, MpcError> {
    PartialSignature::combine(partials)
        .ok_or_else(|| MpcError::Signing("failed to combine partial signatures — possible cheating".into()))
}

/// Full signing in one shot (all MPC rounds inline, no presignature).
pub async fn sign_full<D>(
    eid: ExecutionId<'_>,
    party_index_in_signing: u16,
    parties_indexes_at_keygen: &[u16],
    key_share: &cggmp21::KeyShare<Secp256k1>,
    message_hash: &[u8; 32],
    delivery: D,
) -> Result<CggmpSignature<Secp256k1>, MpcError>
where
    D: cggmp21::round_based::Delivery<
        cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>,
    >,
{
    tracing::info!(
        party_index_in_signing,
        ?parties_indexes_at_keygen,
        "starting full signing"
    );

    let data = DataToSign::from_digest(sha2::Sha256::new_with_prefix(message_hash));
    let party = cggmp21::round_based::MpcParty::connected(delivery);

    let sig = cggmp21::signing(eid, party_index_in_signing, parties_indexes_at_keygen, key_share)
        .sign(&mut OsRng, party, data)
        .await
        .map_err(|e| MpcError::Signing(format!("{e:?}")))?;

    tracing::info!("full signing complete");
    Ok(sig)
}

use sha2::Digest as _;
