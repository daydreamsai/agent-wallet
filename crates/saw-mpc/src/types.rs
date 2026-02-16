use serde::{Deserialize, Serialize};

/// Party identifier in the threshold scheme.
/// 0 = saw-daemon, 1 = saw-policy, 2 = saw-cosigner (human)
pub type PartyId = u16;

pub const PARTY_DAEMON: PartyId = 0;
pub const PARTY_POLICY: PartyId = 1;
pub const PARTY_COSIGNER: PartyId = 2;

/// Configuration for a threshold signing setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// This party's index (0, 1, or 2)
    pub party_id: PartyId,
    /// Threshold required to sign (default: 2)
    pub threshold: u16,
    /// Total number of parties (default: 3)
    pub num_parties: u16,
    /// Wallet name
    pub wallet: String,
    /// Chain type
    pub chain: Chain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Evm,
    Sol,
}

impl ThresholdConfig {
    /// Standard 2-of-3 config for a given party.
    pub fn new_2of3(party_id: PartyId, wallet: &str, chain: Chain) -> Self {
        Self {
            party_id,
            threshold: 2,
            num_parties: 3,
            wallet: wallet.to_string(),
            chain,
        }
    }

    /// 2-of-2 config (no human recovery share).
    pub fn new_2of2(party_id: PartyId, wallet: &str, chain: Chain) -> Self {
        Self {
            party_id,
            threshold: 2,
            num_parties: 2,
            wallet: wallet.to_string(),
            chain,
        }
    }
}

/// Metadata stored alongside the serialized cggmp21 key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareData {
    /// SAW threshold config
    pub config: ThresholdConfig,
    /// Ethereum address derived from the combined public key
    pub address: String,
    /// Hex-encoded combined public key
    pub public_key: String,
    /// Creation timestamp (unix seconds)
    pub created_at: u64,
}
