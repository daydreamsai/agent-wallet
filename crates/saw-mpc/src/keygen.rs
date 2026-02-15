//! Key generation ceremony: all parties collaborate to produce
//! key shares without any single party ever seeing the full key.

use rand_core::OsRng;
use sha3::{Digest, Keccak256};

use cggmp21::supported_curves::Secp256k1;
use cggmp21::{
    key_share::AuxInfo,
    ExecutionId, IncompleteKeyShare, PregeneratedPrimes,
};

use crate::error::MpcError;
use crate::types::KeyShareData;

/// Output of a successful keygen ceremony.
pub struct KeygenOutput {
    pub key_share: cggmp21::KeyShare<Secp256k1>,
    pub address: String,
    pub public_key: String,
}

/// Generate precomputed Paillier primes (CPU-intensive).
pub fn pregenerate_primes() -> PregeneratedPrimes {
    tracing::info!("generating Paillier primes (this may take a while)...");
    let primes = PregeneratedPrimes::generate(&mut OsRng);
    tracing::info!("prime generation complete");
    primes
}

/// Run aux info generation using a `Delivery` transport.
pub async fn generate_aux_info<D>(
    eid: ExecutionId<'_>,
    party_id: u16,
    num_parties: u16,
    primes: PregeneratedPrimes,
    delivery: D,
) -> Result<AuxInfo, MpcError>
where
    D: cggmp21::round_based::Delivery<
        cggmp21::key_refresh::msg::aux_only::Msg<
            sha2::Sha256,
            cggmp21::security_level::SecurityLevel128,
        >,
    >,
{
    tracing::info!(party_id, num_parties, "starting aux info generation");

    let party = cggmp21::round_based::MpcParty::connected(delivery);

    let aux_info = cggmp21::aux_info_gen(eid, party_id, num_parties, primes)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| MpcError::AuxInfo(format!("{e:?}")))?;

    tracing::info!(party_id, "aux info generation complete");
    Ok(aux_info)
}

/// Run distributed key generation using a `Delivery` transport.
pub async fn generate_key<D>(
    eid: ExecutionId<'_>,
    party_id: u16,
    num_parties: u16,
    threshold: u16,
    delivery: D,
) -> Result<IncompleteKeyShare<Secp256k1>, MpcError>
where
    D: cggmp21::round_based::Delivery<
        cggmp21::keygen::ThresholdMsg<
            Secp256k1,
            cggmp21::security_level::SecurityLevel128,
            sha2::Sha256,
        >,
    >,
{
    tracing::info!(party_id, num_parties, threshold, "starting key generation");

    let party = cggmp21::round_based::MpcParty::connected(delivery);

    let incomplete = cggmp21::keygen::<Secp256k1>(eid, party_id, num_parties)
        .set_threshold(threshold)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| MpcError::Keygen(format!("{e:?}")))?;

    tracing::info!(party_id, "key generation complete");
    Ok(incomplete)
}

/// Combine IncompleteKeyShare + AuxInfo → complete KeyShare + derive ETH address.
pub fn complete_key_share(
    incomplete: IncompleteKeyShare<Secp256k1>,
    aux_info: AuxInfo,
) -> Result<KeygenOutput, MpcError> {
    let key_share = cggmp21::KeyShare::from_parts((incomplete, aux_info))
        .map_err(|e| MpcError::Keygen(format!("failed to combine key share: {e:?}")))?;

    // Derive Ethereum address from shared public key
    let public_key_point = key_share.shared_public_key;
    let encoded = public_key_point.to_bytes(false);
    let pub_bytes = encoded.as_ref();
    let public_key = format!("0x{}", hex::encode(pub_bytes));

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex::encode(&hash[12..]));

    tracing::info!(address = %address, "key share completed");

    Ok(KeygenOutput {
        key_share,
        address,
        public_key,
    })
}

/// Serialize a KeyShare for storage.
pub fn serialize_key_share(
    key_share: &cggmp21::KeyShare<Secp256k1>,
) -> Result<Vec<u8>, MpcError> {
    serde_json::to_vec(key_share).map_err(MpcError::Serde)
}

/// Deserialize a KeyShare from storage.
pub fn deserialize_key_share(
    data: &[u8],
) -> Result<cggmp21::KeyShare<Secp256k1>, MpcError> {
    serde_json::from_slice(data).map_err(MpcError::Serde)
}
