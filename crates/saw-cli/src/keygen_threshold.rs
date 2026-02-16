//! Threshold keygen ceremony CLI.
//!
//! Usage:
//!   # Start relay (run first, on any machine):
//!   saw keygen-threshold --relay --listen 0.0.0.0:9444
//!
//!   # Each party connects to relay:
//!   saw keygen-threshold --party 0 --wallet my-wallet --connect ws://relay:9444
//!   saw keygen-threshold --party 1 --wallet my-wallet --connect ws://relay:9444
//!   saw keygen-threshold --party 2 --wallet my-wallet --connect ws://relay:9444
//!
//! Party roles:
//!   0 = saw-daemon (agent machine)
//!   1 = saw-policy (policy machine)
//!   2 = saw-cosigner (human device, recovery key)

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use saw_mpc::keygen;
use saw_mpc::relay;
use saw_mpc::types::{KeyShareData, ThresholdConfig};
use saw_mpc::types::Chain;

const NUM_PARTIES: u16 = 3;
const THRESHOLD: u16 = 2;

/// Run the relay server (no key material, just routes messages).
pub async fn run_relay(listen_addr: &str) -> Result<String, String> {
    eprintln!("=== SAW Keygen Relay Server ===");
    eprintln!("Listening on: {listen_addr}");
    eprintln!("Waiting for {NUM_PARTIES} parties to connect...\n");

    relay::run_relay(listen_addr, NUM_PARTIES)
        .await
        .map_err(|e| format!("relay error: {e}"))?;

    Ok("Relay: all parties disconnected, ceremony complete.".into())
}

/// Run a keygen party (generates and saves a key share).
pub async fn run_party(
    party_id: u16,
    wallet: &str,
    connect_url: &str,
    root: &Path,
) -> Result<String, String> {
    if party_id >= NUM_PARTIES {
        return Err(format!("party must be 0, 1, or 2 (got {party_id})"));
    }

    let role = match party_id {
        0 => "saw-daemon",
        1 => "saw-policy",
        2 => "saw-cosigner",
        _ => unreachable!(),
    };

    eprintln!("=== SAW Threshold Keygen (Party {party_id} / {role}) ===");
    eprintln!("Wallet: {wallet}");
    eprintln!("Connecting to relay: {connect_url}\n");

    // Phase 1: Generate Paillier primes (local, CPU-intensive)
    eprintln!("[1/4] Generating Paillier primes (this takes ~1 minute)...");
    let primes = keygen::pregenerate_primes();
    eprintln!("  ✓ Primes ready\n");

    // Phase 2: Connect to relay and run aux info generation
    eprintln!("[2/4] Connecting to relay for aux info generation...");
    let aux_delivery = relay::connect_to_relay(connect_url, party_id, "aux")
        .await
        .map_err(|e| format!("connect for aux: {e}"))?;

    eprintln!("  Connected! Running aux info generation (MPC)...");

    let aux_eid_bytes = format!("keygen-{wallet}-aux");
    let aux_eid = cggmp21::ExecutionId::new(aux_eid_bytes.as_bytes());
    let aux_info = keygen::generate_aux_info(aux_eid, party_id, NUM_PARTIES, primes, aux_delivery)
        .await
        .map_err(|e| format!("aux info gen failed: {e}"))?;

    eprintln!("  ✓ Aux info complete\n");

    // Phase 3: Key generation
    eprintln!("[3/4] Running key generation (MPC)...");
    let keygen_delivery = relay::connect_to_relay(connect_url, party_id, "keygen")
        .await
        .map_err(|e| format!("connect for keygen: {e}"))?;

    let keygen_eid_bytes = format!("keygen-{wallet}-dkg");
    let keygen_eid = cggmp21::ExecutionId::new(keygen_eid_bytes.as_bytes());
    let incomplete = keygen::generate_key(keygen_eid, party_id, NUM_PARTIES, THRESHOLD, keygen_delivery)
        .await
        .map_err(|e| format!("keygen failed: {e}"))?;

    eprintln!("  ✓ Key generation complete\n");

    // Phase 4: Complete key share and save
    eprintln!("[4/4] Completing key share...");
    let output = keygen::complete_key_share(incomplete, aux_info)
        .map_err(|e| format!("complete key share: {e}"))?;

    let address = &output.address;
    let public_key = &output.public_key;
    eprintln!("  Address: {address}");
    eprintln!("  Public key: {public_key}");

    // Save key share (encrypted if passphrase provided via SAW_PASSPHRASE env var)
    let share_dir = root.join("keys").join("threshold");
    fs::create_dir_all(&share_dir).map_err(|e| format!("create dir: {e}"))?;

    let share_path = share_dir.join(format!("{wallet}.json"));
    let passphrase = std::env::var("SAW_PASSPHRASE").ok();
    let share_data = match &passphrase {
        Some(pp) if !pp.is_empty() => {
            eprintln!("  🔒 Encrypting key share (Argon2id + ChaCha20-Poly1305)...");
            keygen::serialize_key_share_encrypted(&output.key_share, pp.as_bytes())
                .map_err(|e| format!("encrypt: {e}"))?
        }
        _ => {
            eprintln!("  ⚠️  No SAW_PASSPHRASE set — saving key share UNENCRYPTED");
            keygen::serialize_key_share(&output.key_share)
                .map_err(|e| format!("serialize: {e}"))?
        }
    };

    fs::write(&share_path, &share_data).map_err(|e| format!("write: {e}"))?;
    fs::set_permissions(&share_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod: {e}"))?;

    // Save metadata
    let meta = KeyShareData {
        config: ThresholdConfig::new_2of3(party_id, wallet, Chain::Evm),
        address: address.clone(),
        public_key: public_key.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let meta_path = share_dir.join(format!("{wallet}.meta.json"));
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| format!("serialize meta: {e}"))?;
    fs::write(&meta_path, meta_json).map_err(|e| format!("write meta: {e}"))?;

    eprintln!("  ✓ Key share saved to {}", share_path.display());
    eprintln!("  ✓ Metadata saved to {}\n", meta_path.display());

    eprintln!("=== Keygen Complete! ===");
    eprintln!("Wallet address: {address}");
    eprintln!("Key share for party {party_id} ({role}) saved.");

    if party_id == 2 {
        eprintln!("\n⚠️  IMPORTANT: This is the recovery key share.");
        eprintln!("   Store it safely offline. You only need it if");
        eprintln!("   party 0 or party 1 is compromised/lost.");
    }

    Ok(format!("{address}\n"))
}
