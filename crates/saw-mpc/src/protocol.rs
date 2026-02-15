//! Protocol coordination: ties together keygen, presigning, and signing
//! with the transport layer and session management.

use serde::{Deserialize, Serialize};

use crate::types::PartyId;

/// Unique identifier for an MPC protocol execution.
/// Must never be reused across different protocol runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    /// Generate a new random session ID.
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Create from a known string (e.g., received from coordinator).
    pub fn from_str(s: &str) -> Self {
        Self(s.to_string())
    }

    /// Convert to cggmp21 ExecutionId bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A request from saw-daemon to saw-policy for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Unique request ID
    pub request_id: String,
    /// Session ID for the MPC protocol execution
    pub session_id: SessionId,
    /// Wallet name
    pub wallet: String,
    /// What action is being performed
    pub action: SignAction,
    /// Transaction details for policy evaluation
    pub tx_details: TxDetails,
    /// The message hash to sign (32 bytes, hex)
    pub message_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignAction {
    EvmTx,
    Eip2612Permit,
}

/// Transaction details sent to saw-policy for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxDetails {
    pub chain_id: Option<u64>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data_len: usize,
    /// Whether this is a contract call (non-empty data)
    pub is_contract_call: bool,
}

/// Policy decision from saw-policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub request_id: String,
    pub decision: Decision,
    /// Which rule matched (for audit)
    pub matched_rule: Option<String>,
    /// Reason if denied or escalated
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Policy approves — proceed with MPC signing
    Approve,
    /// Policy denies — reject the request
    Deny,
    /// Policy escalates — requires human cosigner
    Escalate,
}

/// Wire message between saw-daemon and saw-policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    /// Signing request (daemon → policy)
    SignRequest(SignRequest),
    /// Policy decision (policy → daemon)
    PolicyDecision(PolicyDecision),
    /// MPC protocol message (bidirectional)
    Mpc(MpcWireMessage),
    /// Heartbeat / keepalive
    Ping,
    Pong,
}

/// Serialized MPC round message for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcWireMessage {
    pub session_id: SessionId,
    pub from: PartyId,
    pub to: Option<PartyId>,
    /// Serialized round-based protocol message
    pub data: Vec<u8>,
}
