//! Local threshold keygen: generates all party key shares in one process.
//!
//! Usage:
//!   SAW_PASSPHRASE=secret saw keygen-local --wallet my-wallet [--root ~/.saw]
//!
//! Outputs:
//!   keys/threshold/{wallet}_party0.json  (saw-daemon)
//!   keys/threshold/{wallet}_party1.json  (saw-policy)
//!   keys/threshold/{wallet}_party2.json  (recovery / cosigner)
//!   keys/threshold/{wallet}.meta.json    (shared metadata)

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use saw_mpc::keygen;
use saw_mpc::transport;
use saw_mpc::types::{Chain, KeyShareData, ThresholdConfig};

const NUM_PARTIES: u16 = 3;
const THRESHOLD: u16 = 2;

pub async fn run(wallet: &str, root: &Path) -> Result<String, String> {
    let passphrase = std::env::var("SAW_PASSPHRASE").ok();

    eprintln!("=== SAW Local Keygen (2-of-3) ===");
    eprintln!("Wallet: {wallet}");
    eprintln!("Root:   {}\n", root.display());

    // Phase 1: Generate Paillier primes (CPU-intensive, sequential)
    eprintln!("[1/4] Generating Paillier primes for {NUM_PARTIES} parties...");
    eprintln!("       (This takes ~1-3 minutes with optimized crypto)");
    let mut primes = Vec::with_capacity(NUM_PARTIES as usize);
    for i in 0..NUM_PARTIES {
        eprint!("  Party {i}: generating... ");
        let p = keygen::pregenerate_primes();
        eprintln!("✓");
        primes.push(p);
    }
    eprintln!();

    // Phase 2: Aux info generation (MPC, in-memory)
    eprintln!("[2/4] Running aux info generation (MPC)...");
    let aux_deliveries = transport::in_memory_delivery(NUM_PARTIES);

    let mut aux_handles = Vec::new();
    for (i, (delivery, prime)) in aux_deliveries.into_iter().zip(primes).enumerate() {
        let eid_bytes: Vec<u8> = format!("local-{wallet}-aux").into_bytes();
        aux_handles.push(tokio::spawn(async move {
            let eid = cggmp21::ExecutionId::new(&eid_bytes);
            keygen::generate_aux_info(eid, i as u16, NUM_PARTIES, prime, delivery).await
        }));
    }

    let mut aux_infos = Vec::new();
    for (i, handle) in aux_handles.into_iter().enumerate() {
        let aux = handle
            .await
            .map_err(|e| format!("party {i} aux task panic: {e}"))?
            .map_err(|e| format!("party {i} aux info gen failed: {e}"))?;
        aux_infos.push(aux);
    }
    eprintln!("  ✓ Aux info complete\n");

    // Phase 3: Key generation (MPC, in-memory)
    eprintln!("[3/4] Running key generation (MPC)...");
    let keygen_deliveries = transport::in_memory_delivery(NUM_PARTIES);

    let mut keygen_handles = Vec::new();
    for (i, delivery) in keygen_deliveries.into_iter().enumerate() {
        let eid_bytes: Vec<u8> = format!("local-{wallet}-dkg").into_bytes();
        keygen_handles.push(tokio::spawn(async move {
            let eid = cggmp21::ExecutionId::new(&eid_bytes);
            keygen::generate_key(eid, i as u16, NUM_PARTIES, THRESHOLD, delivery).await
        }));
    }

    let mut incomplete_shares = Vec::new();
    for (i, handle) in keygen_handles.into_iter().enumerate() {
        let share = handle
            .await
            .map_err(|e| format!("party {i} keygen task panic: {e}"))?
            .map_err(|e| format!("party {i} keygen failed: {e}"))?;
        incomplete_shares.push(share);
    }
    eprintln!("  ✓ Key generation complete\n");

    // Phase 4: Complete key shares and save
    eprintln!("[4/4] Completing and saving key shares...");
    let share_dir = root.join("keys").join("threshold");
    fs::create_dir_all(&share_dir).map_err(|e| format!("create dir: {e}"))?;

    let mut address = String::new();
    let mut public_key = String::new();
    let party_names = ["daemon", "policy", "cosigner"];

    for (i, (incomplete, aux)) in incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .enumerate()
    {
        let output = keygen::complete_key_share(incomplete, aux)
            .map_err(|e| format!("party {i} complete failed: {e}"))?;

        if address.is_empty() {
            address = output.address.clone();
            public_key = output.public_key.clone();
        } else {
            assert_eq!(address, output.address, "address mismatch between parties");
        }

        // Save key share (encrypted if passphrase set)
        let share_path = share_dir.join(format!("{wallet}_party{i}.json"));
        let share_data = match &passphrase {
            Some(pp) if !pp.is_empty() => {
                keygen::serialize_key_share_encrypted(&output.key_share, pp.as_bytes())
                    .map_err(|e| format!("encrypt party {i}: {e}"))?
            }
            _ => {
                keygen::serialize_key_share(&output.key_share)
                    .map_err(|e| format!("serialize party {i}: {e}"))?
            }
        };

        fs::write(&share_path, &share_data).map_err(|e| format!("write party {i}: {e}"))?;
        fs::set_permissions(&share_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod party {i}: {e}"))?;

        eprintln!(
            "  Party {i} ({:>9}): {}",
            party_names[i],
            share_path.display()
        );
    }

    // Save metadata
    let meta = KeyShareData {
        config: ThresholdConfig::new_2of3(0, wallet, Chain::Evm),
        address: address.clone(),
        public_key: public_key.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let meta_path = share_dir.join(format!("{wallet}.meta.json"));
    let meta_json =
        serde_json::to_string_pretty(&meta).map_err(|e| format!("serialize meta: {e}"))?;
    fs::write(&meta_path, meta_json).map_err(|e| format!("write meta: {e}"))?;
    eprintln!("  Metadata:              {}", meta_path.display());

    let encrypted_str = if passphrase.as_ref().map_or(false, |p| !p.is_empty()) {
        "🔒 encrypted"
    } else {
        "⚠️  UNENCRYPTED (set SAW_PASSPHRASE to encrypt)"
    };

    eprintln!("\n=== Keygen Complete! ===");
    eprintln!("Address:    {address}");
    eprintln!("Public key: {public_key}");
    eprintln!("Shares:     {encrypted_str}");
    eprintln!("\nDistribute the key shares:");
    eprintln!("  _party0.json → saw-daemon  (agent machine)");
    eprintln!("  _party1.json → saw-policy  (policy server / Railway)");
    eprintln!("  _party2.json → cosigner    (recovery / cold storage)");

    Ok(format!("{address}\n"))
}
