//! saw-policy: Threshold signing policy agent (Share 2).
//!
//! Runs a WebSocket server that saw-daemon connects to. On each sign request:
//! 1. Evaluate policy rules
//! 2. Approve / Deny / Escalate
//! 3. If approved, participate in MPC signing as party 1
//!
//! Configuration via CLI flags or environment variables:
//!   --listen / PORT          Listen address (default: 0.0.0.0:9443)
//!   --config / POLICY_PATH   Policy YAML file (default: policy.yaml)
//!   --root / SAW_ROOT        Data directory (default: ~/.saw-policy)
//!   --share / KEY_SHARE_PATH Key share file (default: <root>/key_share.json)
//!   SAW_PASSPHRASE           Passphrase to decrypt key share

use std::path::{Path, PathBuf};

mod policy;
mod server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("saw_policy=info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Err(e) = run(args).await {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let mut iter = args.iter();

    // Defaults (overridden by CLI flags, then env vars)
    let mut config_path: Option<PathBuf> = None;
    let mut listen: Option<String> = None;
    let mut root: Option<PathBuf> = None;
    let mut share_path: Option<PathBuf> = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!(
                    "saw-policy - Threshold signing policy agent\n\n\
                     Usage: saw-policy [options]\n\n\
                     Options:\n  \
                       --config <path>  Policy YAML (default: policy.yaml, env: POLICY_PATH)\n  \
                       --listen <addr>  Listen address (default: 0.0.0.0:9443, env: PORT)\n  \
                       --root <path>    Data directory (default: ~/.saw-policy, env: SAW_ROOT)\n  \
                       --share <path>   Key share file (default: <root>/key_share.json, env: KEY_SHARE_PATH)\n  \
                       --help           Show this help\n\n\
                     Environment:\n  \
                       SAW_PASSPHRASE   Passphrase to decrypt encrypted key shares\n  \
                       PORT             Listen port (Railway-style, sets 0.0.0.0:<PORT>)\n"
                );
                return Ok(());
            }
            "--config" => {
                config_path = Some(PathBuf::from(iter.next().ok_or("missing --config value")?));
            }
            "--listen" => {
                listen = Some(iter.next().ok_or("missing --listen value")?.clone());
            }
            "--root" => {
                root = Some(PathBuf::from(iter.next().ok_or("missing --root value")?));
            }
            "--share" => {
                share_path = Some(PathBuf::from(iter.next().ok_or("missing --share value")?));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    // Resolve with env var fallbacks
    let listen = listen.unwrap_or_else(|| {
        if let Ok(port) = std::env::var("PORT") {
            format!("0.0.0.0:{port}")
        } else {
            "0.0.0.0:9443".to_string()
        }
    });

    let config_path = config_path.unwrap_or_else(|| {
        PathBuf::from(std::env::var("POLICY_PATH").unwrap_or_else(|_| "policy.yaml".into()))
    });

    let root = root.unwrap_or_else(|| {
        if let Ok(r) = std::env::var("SAW_ROOT") {
            PathBuf::from(r)
        } else {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/opt/saw-policy".into()))
                .join(".saw-policy")
        }
    });

    let share_path = share_path.unwrap_or_else(|| {
        if let Ok(p) = std::env::var("KEY_SHARE_PATH") {
            PathBuf::from(p)
        } else {
            root.join("key_share.json")
        }
    });

    // Load policy config
    let policy_config = load_policy(&config_path)?;
    tracing::info!(config = %config_path.display(), "loaded policy");

    // Load key share (with optional decryption)
    let key_share = load_key_share(&share_path)?;
    tracing::info!(share = %share_path.display(), "loaded key share");

    // Start server
    tracing::info!(listen = %listen, "starting saw-policy server");
    server::run(&listen, key_share, policy_config)
        .await
        .map_err(|e| format!("server error: {e}"))
}

fn load_policy(path: &Path) -> Result<policy::PolicyConfig, String> {
    // Try POLICY_YAML env var first (inline config for containerized deployments)
    let contents = if let Ok(yaml) = std::env::var("POLICY_YAML") {
        tracing::info!("loading policy from POLICY_YAML env var");
        yaml
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| format!("read policy {}: {e}", path.display()))?
    };
    serde_yaml::from_str(&contents).map_err(|e| format!("parse policy: {e}"))
}

fn load_key_share(path: &Path) -> Result<saw_mpc::KeyShare<saw_mpc::Secp256k1>, String> {
    // Try KEY_SHARE_BASE64 env var first (for containerized deployments)
    let data = if let Ok(b64) = std::env::var("KEY_SHARE_BASE64") {
        use base64::Engine;
        tracing::info!("loading key share from KEY_SHARE_BASE64 env var");
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("decode KEY_SHARE_BASE64: {e}"))?
    } else {
        std::fs::read(path)
            .map_err(|e| format!("read key share {}: {e}", path.display()))?
    };

    let passphrase = std::env::var("SAW_PASSPHRASE").unwrap_or_default();

    if saw_mpc::encryption::is_encrypted(&data) && passphrase.is_empty() {
        return Err("key share is encrypted but SAW_PASSPHRASE not set".into());
    }

    saw_mpc::keygen::deserialize_key_share_encrypted(&data, passphrase.as_bytes())
        .map_err(|e| format!("parse key share: {e}"))
}
