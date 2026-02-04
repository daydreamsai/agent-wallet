use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey as SolSigningKey};
use ethereum_types::U256;
use k256::ecdsa::SigningKey as EvmSigningKey;
use rlp::RlpStream;
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub enum DaemonError {
    Io(io::Error),
    Json(serde_json::Error),
}

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug)]
enum ReadError {
    Io(io::Error),
    TooLarge,
    InvalidUtf8,
}

impl From<io::Error> for DaemonError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DaemonError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Deserialize)]
struct Request {
    request_id: String,
    action: String,
    wallet: String,
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Response {
    request_id: String,
    status: String,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Chain {
    Evm,
    Sol,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct WalletPolicy {
    chain: Chain,
    #[serde(default)]
    allowed_chains: Option<Vec<u64>>,
    #[serde(default)]
    max_tx_value_eth: Option<f64>,
    #[serde(default)]
    allow_contract_calls: Option<bool>,
    #[serde(default)]
    allowlist_addresses: Option<Vec<String>>,
    #[serde(default)]
    rate_limit_per_minute: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    #[serde(default)]
    wallets: HashMap<String, WalletPolicy>,
}

#[derive(Debug, Deserialize)]
struct EvmTxPayload {
    chain_id: u64,
    nonce: u64,
    to: String,
    value: String,
    gas_limit: u64,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct SolTxPayload {
    message_base64: String,
}

#[derive(Debug, Deserialize)]
struct Eip2612PermitPayload {
    chain_id: u64,
    token: String,
    name: String,
    version: String,
    spender: String,
    value: String,
    nonce: String,
    deadline: String,
    #[serde(default)]
    owner: Option<String>,
}

struct Server {
    root: PathBuf,
    rate_state: HashMap<String, Vec<Instant>>,
}

impl Server {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            rate_state: HashMap::new(),
        }
    }

    fn handle_request(&mut self, raw: &str) -> Response {
        let parsed: Result<Request, _> = serde_json::from_str(raw.trim());
        let request = match parsed {
            Ok(value) => value,
            Err(err) => {
                let response = Response {
                    request_id: "unknown".to_string(),
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("invalid json: {err}")),
                };
                let _ = self.log_event("unknown", "unknown", &response.status, None);
                return response;
            }
        };

        let wallet = request.wallet.clone();
        let action = request.action.clone();

        let mut response = match request.action.as_str() {
            "get_address" => self.handle_get_address(request),
            "sign_evm_tx" => self.handle_sign_evm_tx(request),
            "sign_sol_tx" => self.handle_sign_sol_tx(request),
            "sign_eip2612_permit" => self.handle_sign_eip2612_permit(request),
            _ => Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some("unsupported action".to_string()),
            },
        };

        let tx_hash = response
            .result
            .as_ref()
            .and_then(|value| value.get("tx_hash"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        if let Err(_) = self.log_event(&wallet, &action, &response.status, tx_hash.as_deref()) {
            response = Response {
                request_id: response.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some("audit log failure".to_string()),
            };
        }

        response
    }

    fn handle_get_address(&self, request: Request) -> Response {
        match get_address(&self.root, &request.wallet) {
            Ok(payload) => Response {
                request_id: request.request_id,
                status: "approved".to_string(),
                result: Some(payload),
                error: None,
            },
            Err(err) => Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some(err),
            },
        }
    }

    fn handle_sign_evm_tx(&mut self, request: Request) -> Response {
        let payload: EvmTxPayload = match serde_json::from_value(request.payload) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("invalid payload: {err}")),
                }
            }
        };

        let policy = match self.load_wallet_policy(&request.wallet) {
            Ok(policy) => policy,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        if policy.chain != Chain::Evm {
            return Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some("wallet chain mismatch".to_string()),
            };
        }

        if let Some(allowed) = &policy.allowed_chains {
            if !allowed.contains(&payload.chain_id) {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("chain_id not allowed".to_string()),
                };
            }
        }

        if let Some(allowlist) = &policy.allowlist_addresses {
            let to_norm = normalize_hex_address(&payload.to);
            if !allowlist
                .iter()
                .any(|addr| normalize_hex_address(addr) == to_norm)
            {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("destination not allowed".to_string()),
                };
            }
        }

        if policy.allow_contract_calls == Some(false) {
            let data = payload.data.trim_start_matches("0x");
            if !data.is_empty() {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("contract calls not allowed".to_string()),
                };
            }
        }

        if let Some(max_eth) = policy.max_tx_value_eth {
            if let Ok(value_wei) = parse_u256(&payload.value) {
                let max_wei = U256::from((max_eth * 1e18).round() as u128);
                if value_wei > max_wei {
                    return Response {
                        request_id: request.request_id,
                        status: "denied".to_string(),
                        result: None,
                        error: Some("value exceeds limit".to_string()),
                    };
                }
            }
        }

        if let Some(limit) = policy.rate_limit_per_minute {
            if !self.check_rate_limit(&request.wallet, limit as usize) {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("rate limit exceeded".to_string()),
                };
            }
        }

        let key_bytes = match read_key_bytes(&self.root, Chain::Evm, &request.wallet) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        match sign_evm_tx(&key_bytes, payload) {
            Ok(result) => Response {
                request_id: request.request_id,
                status: "approved".to_string(),
                result: Some(result),
                error: None,
            },
            Err(err) => Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some(err),
            },
        }
    }

    fn handle_sign_sol_tx(&mut self, request: Request) -> Response {
        let payload: SolTxPayload = match serde_json::from_value(request.payload) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("invalid payload: {err}")),
                }
            }
        };

        let policy = match self.load_wallet_policy(&request.wallet) {
            Ok(policy) => policy,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        if policy.chain != Chain::Sol {
            return Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some("wallet chain mismatch".to_string()),
            };
        }

        if let Some(limit) = policy.rate_limit_per_minute {
            if !self.check_rate_limit(&request.wallet, limit as usize) {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("rate limit exceeded".to_string()),
                };
            }
        }

        let key_bytes = match read_key_bytes(&self.root, Chain::Sol, &request.wallet) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        match sign_sol_tx(&key_bytes, &payload.message_base64) {
            Ok(result) => Response {
                request_id: request.request_id,
                status: "approved".to_string(),
                result: Some(result),
                error: None,
            },
            Err(err) => Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some(err),
            },
        }
    }

    fn handle_sign_eip2612_permit(&mut self, request: Request) -> Response {
        let payload: Eip2612PermitPayload = match serde_json::from_value(request.payload) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(format!("invalid payload: {err}")),
                }
            }
        };

        let policy = match self.load_wallet_policy(&request.wallet) {
            Ok(policy) => policy,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        if policy.chain != Chain::Evm {
            return Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some("wallet chain mismatch".to_string()),
            };
        }

        if let Some(allowed) = &policy.allowed_chains {
            if !allowed.contains(&payload.chain_id) {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("chain_id not allowed".to_string()),
                };
            }
        }

        if let Some(allowlist) = &policy.allowlist_addresses {
            let token_norm = normalize_hex_address(&payload.token);
            let spender_norm = normalize_hex_address(&payload.spender);
            let token_allowed = allowlist
                .iter()
                .any(|addr| normalize_hex_address(addr) == token_norm);
            let spender_allowed = allowlist
                .iter()
                .any(|addr| normalize_hex_address(addr) == spender_norm);
            if !token_allowed || !spender_allowed {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("permit address not allowed".to_string()),
                };
            }
        }

        if let Some(limit) = policy.rate_limit_per_minute {
            if !self.check_rate_limit(&request.wallet, limit as usize) {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some("rate limit exceeded".to_string()),
                };
            }
        }

        let key_bytes = match read_key_bytes(&self.root, Chain::Evm, &request.wallet) {
            Ok(value) => value,
            Err(err) => {
                return Response {
                    request_id: request.request_id,
                    status: "denied".to_string(),
                    result: None,
                    error: Some(err),
                }
            }
        };

        match sign_eip2612_permit(&key_bytes, payload) {
            Ok(result) => Response {
                request_id: request.request_id,
                status: "approved".to_string(),
                result: Some(result),
                error: None,
            },
            Err(err) => Response {
                request_id: request.request_id,
                status: "denied".to_string(),
                result: None,
                error: Some(err),
            },
        }
    }

    fn load_wallet_policy(&self, wallet: &str) -> Result<WalletPolicy, String> {
        let policy_path = self.root.join("policy.yaml");
        let contents = fs::read_to_string(&policy_path).map_err(|e| e.to_string())?;
        let policy: Policy = serde_yaml::from_str(&contents).map_err(|e| e.to_string())?;
        policy
            .wallets
            .get(wallet)
            .cloned()
            .ok_or_else(|| "wallet not in policy".to_string())
    }

    fn check_rate_limit(&mut self, wallet: &str, limit: usize) -> bool {
        let now = Instant::now();
        let entries = self.rate_state.entry(wallet.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) <= Duration::from_secs(60));
        if entries.len() >= limit {
            return false;
        }
        entries.push(now);
        true
    }

    fn log_event(
        &self,
        wallet: &str,
        action: &str,
        status: &str,
        tx_hash: Option<&str>,
    ) -> Result<(), io::Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut line = format!("ts={} wallet={} action={} status={}", ts, wallet, action, status);
        if let Some(hash) = tx_hash {
            line.push_str(&format!(" tx_hash={}", hash));
        }
        line.push('\n');

        let log_path = self.root.join("audit.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&log_path)?;
        file.write_all(line.as_bytes())?;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o640))?;
        Ok(())
    }
}

pub fn serve_once(socket_path: &Path, root: &Path) -> Result<(), DaemonError> {
    serve_n(socket_path, root, 1)
}

pub fn serve_n(socket_path: &Path, root: &Path, count: usize) -> Result<(), DaemonError> {
    serve_loop(socket_path, root, Some(count), None)
}

pub fn serve_forever(socket_path: &Path, root: &Path) -> Result<(), DaemonError> {
    serve_loop(socket_path, root, None, None)
}

pub fn serve_forever_with_shutdown(
    socket_path: &Path,
    root: &Path,
    stop: Arc<AtomicBool>,
) -> Result<(), DaemonError> {
    serve_loop(socket_path, root, None, Some(stop))
}

fn read_request(stream: &mut impl Read) -> Result<String, ReadError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut too_large = false;

    loop {
        let read = stream.read(&mut chunk).map_err(ReadError::Io)?;
        if read == 0 {
            break;
        }

        if too_large {
            continue;
        }

        if buf.len() + read > MAX_REQUEST_BYTES {
            too_large = true;
            continue;
        }

        buf.extend_from_slice(&chunk[..read]);
    }

    if too_large {
        return Err(ReadError::TooLarge);
    }

    String::from_utf8(buf).map_err(|_| ReadError::InvalidUtf8)
}

fn serve_loop(
    socket_path: &Path,
    root: &Path,
    limit: Option<usize>,
    stop: Option<Arc<AtomicBool>>,
) -> Result<(), DaemonError> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    listener.set_nonblocking(true)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;

    let mut server = Server::new(root);
    let mut handled = 0usize;

    loop {
        if let Some(stop_flag) = &stop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                let response = match read_request(&mut stream) {
                    Ok(raw) => server.handle_request(&raw),
                    Err(ReadError::TooLarge) => {
                        let response = Response {
                            request_id: "unknown".to_string(),
                            status: "denied".to_string(),
                            result: None,
                            error: Some("request too large".to_string()),
                        };
                        let _ = server.log_event("unknown", "unknown", &response.status, None);
                        response
                    }
                    Err(ReadError::InvalidUtf8) => {
                        let response = Response {
                            request_id: "unknown".to_string(),
                            status: "denied".to_string(),
                            result: None,
                            error: Some("invalid utf8".to_string()),
                        };
                        let _ = server.log_event("unknown", "unknown", &response.status, None);
                        response
                    }
                    Err(ReadError::Io(err)) => return Err(DaemonError::Io(err)),
                };

                let body = serde_json::to_string(&response)?;
                stream.write_all(body.as_bytes())?;
                handled += 1;
                if let Some(limit) = limit {
                    if handled >= limit {
                        break;
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(DaemonError::Io(err)),
        }
    }

    let _ = fs::remove_file(socket_path);
    Ok(())
}

fn get_address(root: &Path, wallet: &str) -> Result<serde_json::Value, String> {
    let evm_path = root.join("keys").join("evm").join(format!("{}.key", wallet));
    let sol_path = root.join("keys").join("sol").join(format!("{}.key", wallet));

    let evm_exists = evm_path.exists();
    let sol_exists = sol_path.exists();

    let (chain, key_bytes) = match (evm_exists, sol_exists) {
        (true, false) => (Chain::Evm, fs::read(&evm_path).map_err(|e| e.to_string())?),
        (false, true) => (Chain::Sol, fs::read(&sol_path).map_err(|e| e.to_string())?),
        (true, true) => return Err("wallet exists on multiple chains".to_string()),
        (false, false) => return Err("wallet not found".to_string()),
    };

    match chain {
        Chain::Evm => derive_evm_address(&key_bytes),
        Chain::Sol => derive_sol_address(&key_bytes),
    }
}

fn derive_evm_address(key_bytes: &[u8]) -> Result<serde_json::Value, String> {
    if key_bytes.len() != 32 {
        return Err("invalid evm key length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);

    let signing_key = EvmSigningKey::from_bytes((&key).into())
        .map_err(|_| "invalid evm private key".to_string())?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex::encode(&hash[12..]));
    let public_key = format!("0x{}", hex::encode(pub_bytes));

    Ok(json!({
        "address": address,
        "public_key": public_key,
        "chain": "evm"
    }))
}

fn derive_sol_address(key_bytes: &[u8]) -> Result<serde_json::Value, String> {
    if key_bytes.len() != 64 {
        return Err("invalid sol key length".to_string());
    }

    let public = &key_bytes[32..];
    let address = bs58::encode(public).into_string();
    let public_key = bs58::encode(public).into_string();

    Ok(json!({
        "address": address,
        "public_key": public_key,
        "chain": "sol"
    }))
}

fn read_key_bytes(root: &Path, chain: Chain, wallet: &str) -> Result<Vec<u8>, String> {
    let dir = match chain {
        Chain::Evm => "evm",
        Chain::Sol => "sol",
    };
    let path = root.join("keys").join(dir).join(format!("{}.key", wallet));
    fs::read(&path).map_err(|e| e.to_string())
}

fn sign_evm_tx(key_bytes: &[u8], payload: EvmTxPayload) -> Result<serde_json::Value, String> {
    if key_bytes.len() != 32 {
        return Err("invalid evm key length".to_string());
    }

    let to = parse_hex_address(&payload.to)?;
    let value = parse_u256(&payload.value).map_err(|_| "invalid value".to_string())?;
    let max_fee = parse_u256(&payload.max_fee_per_gas).map_err(|_| "invalid max_fee".to_string())?;
    let max_priority =
        parse_u256(&payload.max_priority_fee_per_gas).map_err(|_| "invalid max_priority".to_string())?;
    let data = parse_hex_bytes(&payload.data)?;

    let mut rlp = RlpStream::new_list(9);
    rlp.append(&payload.chain_id);
    rlp.append(&payload.nonce);
    rlp.append(&max_priority);
    rlp.append(&max_fee);
    rlp.append(&payload.gas_limit);
    rlp.append(&to.as_slice());
    rlp.append(&value);
    rlp.append(&data);
    rlp.begin_list(0);

    let mut sighash_input = vec![0x02];
    sighash_input.extend(rlp.out());
    let sighash = Keccak256::digest(&sighash_input);

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(key_bytes).map_err(|_| "invalid evm key".to_string())?;
    let message = Message::from_digest_slice(&sighash).map_err(|_| "invalid sighash".to_string())?;
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret);
    let (rec_id, sig_bytes) = sig.serialize_compact();
    let y_parity = rec_id.to_i32() as u8;

    let r_val = U256::from_big_endian(&sig_bytes[0..32]);
    let s_val = U256::from_big_endian(&sig_bytes[32..64]);

    let mut rlp_signed = RlpStream::new_list(12);
    rlp_signed.append(&payload.chain_id);
    rlp_signed.append(&payload.nonce);
    rlp_signed.append(&max_priority);
    rlp_signed.append(&max_fee);
    rlp_signed.append(&payload.gas_limit);
    rlp_signed.append(&to.as_slice());
    rlp_signed.append(&value);
    rlp_signed.append(&data);
    rlp_signed.begin_list(0);
    rlp_signed.append(&y_parity);
    rlp_signed.append(&r_val);
    rlp_signed.append(&s_val);

    let mut raw_tx = vec![0x02];
    raw_tx.extend(rlp_signed.out());

    let mut hasher = Keccak256::new();
    hasher.update(&raw_tx);
    let tx_hash = format!("0x{}", hex::encode(hasher.finalize()));
    let raw_tx_hex = format!("0x{}", hex::encode(raw_tx));

    Ok(json!({
        "raw_tx": raw_tx_hex,
        "tx_hash": tx_hash
    }))
}

fn sign_sol_tx(key_bytes: &[u8], message_base64: &str) -> Result<serde_json::Value, String> {
    if key_bytes.len() != 64 {
        return Err("invalid sol key length".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&key_bytes[..32]);
    let signing_key = SolSigningKey::from_bytes(&secret);

    let message = general_purpose::STANDARD
        .decode(message_base64)
        .map_err(|_| "invalid message base64".to_string())?;

    let signature = signing_key.sign(&message);
    let sig_bytes = signature.to_bytes();
    let sig_b58 = bs58::encode(sig_bytes).into_string();

    let mut signed_tx = Vec::with_capacity(1 + sig_bytes.len() + message.len());
    signed_tx.push(1);
    signed_tx.extend_from_slice(&sig_bytes);
    signed_tx.extend_from_slice(&message);

    let signed_b64 = general_purpose::STANDARD.encode(signed_tx);

    Ok(json!({
        "signature": sig_b58,
        "signed_tx_base64": signed_b64
    }))
}

fn sign_eip2612_permit(
    key_bytes: &[u8],
    payload: Eip2612PermitPayload,
) -> Result<serde_json::Value, String> {
    if key_bytes.len() != 32 {
        return Err("invalid evm key length".to_string());
    }

    let owner_bytes = evm_address_bytes(key_bytes)?;
    if let Some(owner) = payload.owner.as_deref() {
        let payload_owner = parse_hex_address_fixed(owner)
            .map_err(|_| "invalid owner address".to_string())?;
        if payload_owner != owner_bytes {
            return Err("owner mismatch".to_string());
        }
    }

    let token = parse_hex_address_fixed(&payload.token)?;
    let spender = parse_hex_address_fixed(&payload.spender)?;
    let value = parse_u256(&payload.value).map_err(|_| "invalid value".to_string())?;
    let nonce = parse_u256(&payload.nonce).map_err(|_| "invalid nonce".to_string())?;
    let deadline = parse_u256(&payload.deadline).map_err(|_| "invalid deadline".to_string())?;

    let domain_separator = eip712_domain_separator(
        &payload.name,
        &payload.version,
        payload.chain_id,
        &token,
    );
    let struct_hash = eip2612_permit_hash(&owner_bytes, &spender, value, nonce, deadline);
    let digest = eip712_digest(domain_separator, struct_hash);

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(key_bytes).map_err(|_| "invalid evm key".to_string())?;
    let message = Message::from_digest_slice(&digest).map_err(|_| "invalid digest".to_string())?;
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret);
    let (rec_id, sig_bytes) = sig.serialize_compact();
    let v = (rec_id.to_i32() as u8) + 27;

    let mut sig_out = [0u8; 65];
    sig_out[..64].copy_from_slice(&sig_bytes);
    sig_out[64] = v;
    let signature = format!("0x{}", hex::encode(sig_out));

    Ok(json!({
        "signature": signature
    }))
}

fn parse_hex_address(value: &str) -> Result<Vec<u8>, String> {
    let normalized = value.trim_start_matches("0x");
    let bytes = hex::decode(normalized).map_err(|_| "invalid address".to_string())?;
    if bytes.len() != 20 {
        return Err("invalid address length".to_string());
    }
    Ok(bytes)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let normalized = value.trim_start_matches("0x");
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(normalized).map_err(|_| "invalid hex".to_string())
}

fn parse_u256(value: &str) -> Result<U256, ()> {
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        U256::from_dec_str(value).map_err(|_| ())
    }
}

fn normalize_hex_address(value: &str) -> String {
    let trimmed = value.trim_start_matches("0x");
    format!("0x{}", trimmed.to_lowercase())
}

fn parse_hex_address_fixed(value: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex_address(value)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn evm_address_bytes(key_bytes: &[u8]) -> Result<[u8; 20], String> {
    if key_bytes.len() != 32 {
        return Err("invalid evm key length".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);

    let signing_key = EvmSigningKey::from_bytes((&key).into())
        .map_err(|_| "invalid evm private key".to_string())?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let hash = hasher.finalize();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

fn pad_u256(value: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    value.to_big_endian(&mut out);
    out
}

fn pad_address(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    out
}

fn keccak256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn eip712_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> [u8; 32] {
    let type_hash = keccak256_bytes(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256_bytes(name.as_bytes());
    let version_hash = keccak256_bytes(version.as_bytes());

    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&name_hash);
    encoded.extend_from_slice(&version_hash);
    encoded.extend_from_slice(&pad_u256(U256::from(chain_id)));
    encoded.extend_from_slice(&pad_address(verifying_contract));

    keccak256_bytes(&encoded)
}

fn eip2612_permit_hash(
    owner: &[u8; 20],
    spender: &[u8; 20],
    value: U256,
    nonce: U256,
    deadline: U256,
) -> [u8; 32] {
    let type_hash = keccak256_bytes(
        b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
    );

    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&pad_address(owner));
    encoded.extend_from_slice(&pad_address(spender));
    encoded.extend_from_slice(&pad_u256(value));
    encoded.extend_from_slice(&pad_u256(nonce));
    encoded.extend_from_slice(&pad_u256(deadline));

    keccak256_bytes(&encoded)
}

fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(2 + 32 + 32);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain_separator);
    encoded.extend_from_slice(&struct_hash);
    keccak256_bytes(&encoded)
}

pub mod cli {
    use std::fmt;
    use std::path::PathBuf;
    use std::sync::{
        atomic::AtomicBool,
        Arc,
    };

    use crate::{serve_forever, serve_forever_with_shutdown, serve_n, DaemonError};

    #[derive(Debug)]
    pub enum CliError {
        MissingArg(&'static str),
        InvalidArg(String),
        Daemon(DaemonError),
    }

    impl From<DaemonError> for CliError {
        fn from(value: DaemonError) -> Self {
            Self::Daemon(value)
        }
    }

    impl fmt::Display for CliError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CliError::MissingArg(arg) => write!(f, "missing argument: {arg}"),
                CliError::InvalidArg(arg) => write!(f, "invalid argument: {arg}"),
                CliError::Daemon(err) => write!(f, "daemon failed: {err:?}"),
            }
        }
    }

    pub fn run<I, S>(args: I, limit: Option<usize>) -> Result<(), CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut iter = args.into_iter();
        let mut socket: PathBuf = PathBuf::from("/run/saw.sock");
        let mut root: PathBuf = PathBuf::from("/opt/saw");

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
                "--socket" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--socket"))?
                        .as_ref()
                        .to_string();
                    socket = PathBuf::from(value);
                }
                "--root" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--root"))?
                        .as_ref()
                        .to_string();
                    root = PathBuf::from(value);
                }
                other => return Err(CliError::InvalidArg(format!("flag: {other}"))),
            }
        }

        match limit {
            Some(count) => serve_n(&socket, &root, count)?,
            None => serve_forever(&socket, &root)?,
        }

        Ok(())
    }

    pub fn run_with_shutdown<I, S>(
        args: I,
        stop: Arc<AtomicBool>,
    ) -> Result<(), CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut iter = args.into_iter();
        let mut socket: PathBuf = PathBuf::from("/run/saw.sock");
        let mut root: PathBuf = PathBuf::from("/opt/saw");

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
                "--socket" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--socket"))?
                        .as_ref()
                        .to_string();
                    socket = PathBuf::from(value);
                }
                "--root" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--root"))?
                        .as_ref()
                        .to_string();
                    root = PathBuf::from(value);
                }
                other => return Err(CliError::InvalidArg(format!("flag: {other}"))),
            }
        }

        serve_forever_with_shutdown(&socket, &root, stop)?;
        Ok(())
    }
}
