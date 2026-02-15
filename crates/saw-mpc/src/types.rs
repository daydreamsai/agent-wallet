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
}

/// Wrapper around cggmp21's key share with SAW metadata.
/// The actual cggmp21 KeyShare is stored serialized — we don't
/// re-export cggmp21 types to keep the boundary clean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// SAW threshold config
    pub config: ThresholdConfig,
    /// Ethereum address derived from the combined public key
    pub address: String,
    /// Hex-encoded combined public key
    pub public_key: String,
    /// Serialized cggmp21 IncompleteKeyShare (sensitive!)
    pub incomplete_key_share: Vec<u8>,
    /// Serialized cggmp21 AuxInfo (sensitive!)
    pub aux_info: Vec<u8>,
    /// Creation timestamp (unix seconds)
    pub created_at: u64,
}

/// A message exchanged between parties during MPC protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcMessage {
    /// Unique session/execution ID
    pub session_id: String,
    /// Sender party index
    pub from: PartyId,
    /// Recipient (None = broadcast)
    pub to: Option<PartyId>,
    /// Protocol phase
    pub phase: MpcPhase,
    /// Serialized protocol message
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpcPhase {
    AuxInfo,
    Keygen,
    Presign,
    Sign,
}
