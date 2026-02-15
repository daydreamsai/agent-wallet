//! Signing: presignature generation and online signing.
//!
//! Two-phase approach for minimum latency:
//! 1. Presign (background): 3 MPC rounds between 2 parties → presignature
//! 2. Sign (online): combine presignature + message hash → ECDSA signature
//!
//! Presignatures are message-independent and can be stockpiled.

use crate::error::MpcError;
use crate::types::KeyShare;

/// A presignature share — the output of the presigning protocol.
/// Consumed exactly once to produce a signature.
///
/// SECURITY: Never reuse a presignature for two different messages.
/// Doing so leaks the private key.
#[derive(Debug)]
pub struct Presignature {
    // Will hold cggmp21::Presignature internally
    _placeholder: (),
}

/// An ECDSA signature produced by combining presignature shares.
#[derive(Debug, Clone)]
pub struct Signature {
    /// r component
    pub r: [u8; 32],
    /// s component
    pub s: [u8; 32],
    /// recovery id (0 or 1)
    pub v: u8,
}

impl Signature {
    /// Encode as 65-byte RSV format (r || s || v).
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    /// Hex-encoded signature with 0x prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_rsv()))
    }
}

/// Manages a pool of presignatures for low-latency signing.
pub struct PresignaturePool {
    /// Ready-to-use presignatures
    pool: Vec<Presignature>,
    /// Target pool size
    target_size: usize,
    /// Refill when pool drops below this
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

    /// Take a presignature from the pool. Returns None if empty.
    pub fn take(&mut self) -> Option<Presignature> {
        self.pool.pop()
    }

    /// Number of presignatures available.
    pub fn available(&self) -> usize {
        self.pool.len()
    }

    /// Whether the pool needs refilling.
    pub fn needs_refill(&self) -> bool {
        self.pool.len() < self.refill_threshold
    }

    /// How many presignatures to generate on next refill.
    pub fn refill_count(&self) -> usize {
        self.target_size.saturating_sub(self.pool.len())
    }

    /// Add a presignature to the pool.
    pub fn add(&mut self, presig: Presignature) {
        self.pool.push(presig);
    }
}

/// Generate a presignature by running the presigning protocol
/// between this party and one other party.
///
/// # Protocol Flow
///
/// ```text
/// Party A (e.g., daemon)          Party B (e.g., policy)
///     │                                │
///     ├── Presign Round 1 ────────────►│
///     │◄── Presign Round 1 ────────────┤
///     │                                │
///     ├── Presign Round 2 ────────────►│
///     │◄── Presign Round 2 ────────────┤
///     │                                │
///     ├── Presign Round 3 ────────────►│
///     │◄── Presign Round 3 ────────────┤
///     │                                │
///     │  [Both hold presignature shares]
/// ```
pub async fn generate_presignature(
    _key_share: &KeyShare,
    // TODO: transport, signing party indices
) -> Result<Presignature, MpcError> {
    // TODO: Implement using cggmp21:
    //
    // let eid = cggmp21::ExecutionId::new(session_id.as_bytes());
    // let signers = [PARTY_DAEMON, PARTY_POLICY]; // keygen indices of signing parties
    //
    // let presig = cggmp21::signing(eid, my_index_in_signers, &signers, &key_share)
    //     .generate_presignature(&mut OsRng, party)
    //     .await
    //     .map_err(|e| MpcError::Presign(e.to_string()))?;

    Err(MpcError::Presign("presigning not yet implemented — scaffolding only".into()))
}

/// Sign a message hash using a presignature.
///
/// This is the fast path — single round, no network needed if
/// both partial signatures are available.
///
/// # Protocol Flow
///
/// ```text
/// 1. Each party: presig.issue_partial_signature(hash) → PartialSignature
/// 2. Combine: PartialSignature::combine(&[partial_a, partial_b]) → Signature
/// ```
pub async fn sign_with_presignature(
    _presig: Presignature,
    _message_hash: &[u8; 32],
    // TODO: transport for partial signature exchange
) -> Result<Signature, MpcError> {
    // TODO: Implement using cggmp21:
    //
    // let data = cggmp21::DataToSign::from_digest(message_hash);
    // let partial = presig.issue_partial_signature(data);
    // // Exchange partial signatures with the other party
    // let signature = cggmp21::PartialSignature::combine(&[my_partial, their_partial])?;

    Err(MpcError::Signing("signing not yet implemented — scaffolding only".into()))
}

/// Full signing without a presignature (slower, all rounds inline).
/// Use when presignature pool is empty.
pub async fn sign_full(
    _key_share: &KeyShare,
    _message_hash: &[u8; 32],
    // TODO: transport, signing party indices
) -> Result<Signature, MpcError> {
    // TODO: Implement using cggmp21:
    //
    // let data = cggmp21::DataToSign::from_digest(message_hash);
    // let signature = cggmp21::signing(eid, i, &signers, &key_share)
    //     .sign(&mut OsRng, party, data)
    //     .await?;

    Err(MpcError::Signing("full signing not yet implemented — scaffolding only".into()))
}
