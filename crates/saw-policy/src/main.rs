//! saw-policy: Threshold signing policy agent (Share 2).
//!
//! Runs a WebSocket server that saw-daemon connects to. On each sign request:
//! 1. Evaluate policy rules
//! 2. Approve / Deny / Escalate
//! 3. If approved, participate in MPC signing as party 1

use std::path::PathBuf;

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
    let mut config_path = PathBuf::from("policy.yaml");
    let mut listen = String::from("0.0.0.0:9443");
    let mut root = PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| "/opt/saw-policy".into()),
    )
    .join(".saw-policy");

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!(
                    "saw-policy - Threshold signing policy agent\n\n\
                     Usage: saw-policy [options]\n\n\
                     Options:\n  \
                       --config <path>  Policy YAML file (default: policy.yaml)\n  \
                       --listen <addr>  Listen address (default: 0.0.0.0:9443)\n  \
                       --root <path>    Data directory (default: ~/.saw-policy)\n  \
                       --help           Show this help\n"
                );
                return Ok(());
            }
            "--config" => {
                config_path = PathBuf::from(iter.next().ok_or("missing --config value")?);
            }
            "--listen" => {
                listen = iter.next().ok_or("missing --listen value")?.clone();
            }
            "--root" => {
                root = PathBuf::from(iter.next().ok_or("missing --root value")?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    // Load policy config
    let policy_config = load_policy(&config_path)?;
    tracing::info!(config = %config_path.display(), "loaded policy");

    // Load key share
    let key_share = load_key_share(&root)?;
    tracing::info!(root = %root.display(), "loaded key share");

    // Start server
    server::run(&listen, key_share, policy_config)
        .await
        .map_err(|e| format!("server error: {e}"))
}

fn load_policy(path: &PathBuf) -> Result<policy::PolicyConfig, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("read policy {}: {e}", path.display()))?;
    serde_yaml::from_str(&contents)
        .map_err(|e| format!("parse policy: {e}"))
}

fn load_key_share(root: &PathBuf) -> Result<saw_mpc::KeyShare<saw_mpc::Secp256k1>, String> {
    let share_path = root.join("key_share.json");
    let data = std::fs::read(&share_path)
        .map_err(|e| format!("read key share {}: {e}", share_path.display()))?;
    saw_mpc::keygen::deserialize_key_share(&data)
        .map_err(|e| format!("parse key share: {e}"))
}
