//! saw-mpc: Threshold signing core for SAW
//!
//! Provides CGGMP21-based threshold ECDSA:
//! - Key generation ceremony (all parties)
//! - Auxiliary info generation (Paillier setup)
//! - Presignature generation (t parties, background)
//! - Online signing (single round with presignature)
//!
//! Network-agnostic: callers provide Stream/Sink transports
//! via the `round_based::Delivery` trait.

pub mod encryption;
pub mod error;
pub mod keygen;
pub mod protocol;
pub mod relay;
pub mod signing;
pub mod transport;
pub mod types;

pub use error::MpcError;
pub use types::{KeyShareData, PartyId, ThresholdConfig};

// Re-export key cggmp21 types that consumers need
pub use cggmp21::supported_curves::Secp256k1;
pub use cggmp21::ExecutionId;
pub use cggmp21::KeyShare;
