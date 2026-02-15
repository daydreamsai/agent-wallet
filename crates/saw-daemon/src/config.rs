//! Daemon configuration: signing mode, threshold settings.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level daemon configuration (loaded from config.yaml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Signing mode per wallet. If absent, defaults to single-key.
    #[serde(default)]
    pub wallets: std::collections::HashMap<String, WalletSigningConfig>,
}

/// Signing configuration for a single wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSigningConfig {
    /// Signing mode: "single-key" or "threshold"
    #[serde(default = "default_mode")]
    pub mode: SigningMode,

    /// For threshold mode: URL of the policy agent WebSocket server
    pub policy_url: Option<String>,

    /// For threshold mode: path to the key share file (relative to root)
    pub key_share_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode {
    SingleKey,
    Threshold,
}

fn default_mode() -> SigningMode {
    SigningMode::SingleKey
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            wallets: std::collections::HashMap::new(),
        }
    }
}

/// Load daemon config from file. Returns default if file doesn't exist.
pub fn load_config(root: &Path) -> DaemonConfig {
    let config_path = root.join("config.yaml");
    match std::fs::read_to_string(&config_path) {
        Ok(contents) => {
            serde_yaml::from_str(&contents).unwrap_or_else(|e| {
                eprintln!("warning: invalid config.yaml: {e}, using defaults");
                DaemonConfig::default()
            })
        }
        Err(_) => DaemonConfig::default(),
    }
}
