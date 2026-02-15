use thiserror::Error;

#[derive(Debug, Error)]
pub enum MpcError {
    #[error("keygen failed: {0}")]
    Keygen(String),

    #[error("aux info generation failed: {0}")]
    AuxInfo(String),

    #[error("presigning failed: {0}")]
    Presign(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("invalid party configuration: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
