//! Key generation ceremony: all 3 parties collaborate to produce
//! key shares without any single party ever seeing the full key.
//!
//! Steps:
//! 1. Generate auxiliary info (Paillier moduli, ZK proofs)
//! 2. Run distributed key generation
//! 3. Combine into a complete KeyShare
//! 4. Derive Ethereum address from the combined public key

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::MpcError;
use crate::types::{Chain, KeyShare, ThresholdConfig};

/// Run the full keygen ceremony for this party.
///
/// This is a placeholder that documents the integration points.
/// The actual implementation will wire cggmp21's keygen + aux_info_gen
/// into the transport layer.
///
/// # Protocol Flow
///
/// ```text
/// 1. All parties: aux_info_gen(eid, i, n, primes) → AuxInfo
///    - Generates Paillier keypairs and ZK proofs
///    - Computationally heavy (safe prime generation)
///    - Can be reused across multiple wallets
///
/// 2. All parties: keygen::<Secp256k1>(eid, i, n).set_threshold(t) → IncompleteKeyShare
///    - Generates secret share xi such that x = Σ xi
///    - Outputs combined public key Q
///    - Each party only knows their xi
///
/// 3. Each party: KeyShare::from_parts((incomplete, aux_info)) → KeyShare
///    - Combines keygen output with aux info
///    - Ready for signing
/// ```
pub async fn run_keygen(
    config: &ThresholdConfig,
    // TODO: transport parameter — Stream/Sink of MPC messages
) -> Result<KeyShare, MpcError> {
    if config.threshold < 2 {
        return Err(MpcError::Config("threshold must be >= 2".into()));
    }
    if config.num_parties < config.threshold {
        return Err(MpcError::Config(
            "num_parties must be >= threshold".into(),
        ));
    }
    if config.party_id >= config.num_parties {
        return Err(MpcError::Config(
            "party_id must be < num_parties".into(),
        ));
    }
    if config.chain != Chain::Evm {
        return Err(MpcError::Config(
            "only EVM chain supported for threshold signing".into(),
        ));
    }

    // TODO: Implement actual keygen ceremony:
    //
    // let primes = cggmp21::PregeneratedPrimes::generate(&mut OsRng);
    //
    // let eid = cggmp21::ExecutionId::new(session_id.as_bytes());
    //
    // let aux_info = cggmp21::aux_info_gen(eid, config.party_id, config.num_parties, primes)
    //     .start(&mut OsRng, party)
    //     .await
    //     .map_err(|e| MpcError::AuxInfo(e.to_string()))?;
    //
    // let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, config.party_id, config.num_parties)
    //     .set_threshold(config.threshold)
    //     .start(&mut OsRng, party)
    //     .await
    //     .map_err(|e| MpcError::Keygen(e.to_string()))?;
    //
    // let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))
    //     .map_err(|e| MpcError::Keygen(e.to_string()))?;
    //
    // Derive Ethereum address from key_share.shared_public_key()

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Placeholder — will be replaced with real keygen output
    Err(MpcError::Keygen("keygen not yet implemented — scaffolding only".into()))
}
