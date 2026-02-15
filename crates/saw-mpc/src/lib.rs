//! saw-mpc: Threshold signing core for SAW
//!
//! Provides CGGMP21-based 2-of-3 threshold ECDSA:
//! - Key generation ceremony (all 3 parties)
//! - Auxiliary info generation (Paillier setup)
//! - Presignature generation (2 parties, background)
//! - Online signing (2 parties, single round with presignature)
//!
//! Network-agnostic: callers provide Stream/Sink transports.

pub mod error;
pub mod keygen;
pub mod protocol;
pub mod signing;
pub mod transport;
pub mod types;

pub use error::MpcError;
pub use types::{KeyShare, PartyId, ThresholdConfig};
