use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ed25519_dalek::SigningKey as SolSigningKey;
use k256::ecdsa::SigningKey as EvmSigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Evm,
    Sol,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPolicy {
    pub chain: Chain,
    #[serde(default)]
    pub allowed_chains: Option<Vec<u64>>,
    #[serde(default)]
    pub max_tx_value_eth: Option<f64>,
    #[serde(default)]
    pub allow_contract_calls: Option<bool>,
    #[serde(default)]
    pub allowlist_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
}

impl WalletPolicy {
    fn new(chain: Chain) -> Self {
        Self {
            chain,
            allowed_chains: None,
            max_tx_value_eth: None,
            allow_contract_calls: None,
            allowlist_addresses: None,
            rate_limit_per_minute: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub wallets: BTreeMap<String, WalletPolicy>,
}

#[derive(Debug)]
pub struct GenKeyResult {
    pub address: String,
    pub public_key: String,
}

#[derive(Debug)]
pub enum GenKeyError {
    Io(io::Error),
    AlreadyExists,
    Policy(PolicyError),
}

impl From<io::Error> for GenKeyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<PolicyError> for GenKeyError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

#[derive(Debug)]
pub enum PolicyError {
    Io(io::Error),
    Parse(serde_yaml::Error),
    InvalidPolicy,
    WalletExists,
}

#[derive(Debug)]
pub enum InstallError {
    Io(io::Error),
}

impl From<io::Error> for InstallError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<io::Error> for PolicyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_yaml::Error> for PolicyError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Parse(value)
    }
}

pub fn gen_key(chain: Chain, wallet: &str, root: &Path) -> Result<GenKeyResult, GenKeyError> {
    let (dir_name, key_bytes, chain_value, result) = match chain {
        Chain::Evm => {
            let (key, result) = gen_evm()?;
            ("evm", key, Chain::Evm, result)
        }
        Chain::Sol => {
            let (key, result) = gen_sol()?;
            ("sol", key, Chain::Sol, result)
        }
    };

    let keys_root = root.join("keys");
    fs::create_dir_all(&keys_root)?;
    set_mode(&keys_root, 0o700)?;

    let keys_dir = keys_root.join(dir_name);
    fs::create_dir_all(&keys_dir)?;
    set_mode(&keys_dir, 0o700)?;

    let key_path = keys_dir.join(format!("{}.key", wallet));
    if key_path.exists() {
        return Err(GenKeyError::AlreadyExists);
    }

    let mut key_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)?;
    key_file.write_all(&key_bytes)?;

    let policy_path = root.join("policy.yaml");
    upsert_policy(&policy_path, wallet, chain_value)?;

    Ok(result)
}

fn gen_evm() -> Result<(Vec<u8>, GenKeyResult), GenKeyError> {
    let mut rng = OsRng;
    let signing_key = EvmSigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex::encode(&hash[12..]));
    let public_key = format!("0x{}", hex::encode(pub_bytes));

    let key_bytes = signing_key.to_bytes().to_vec();

    Ok((key_bytes, GenKeyResult { address, public_key }))
}

fn gen_sol() -> Result<(Vec<u8>, GenKeyResult), GenKeyError> {
    let mut rng = OsRng;
    let signing_key = SolSigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let secret = signing_key.to_bytes();
    let public = verifying_key.as_bytes();

    let mut key = vec![0u8; 64];
    key[..32].copy_from_slice(&secret);
    key[32..].copy_from_slice(public);

    let address = bs58::encode(public).into_string();
    let public_key = bs58::encode(public).into_string();

    Ok((key, GenKeyResult { address, public_key }))
}

pub fn validate_policy(policy_path: &Path) -> Result<(), PolicyError> {
    let _policy = read_policy(policy_path)?;
    Ok(())
}

pub fn add_wallet_stub(
    policy_path: &Path,
    wallet: &str,
    chain: Chain,
) -> Result<(), PolicyError> {
    let mut policy = read_policy_or_default(policy_path)?;
    if policy.wallets.contains_key(wallet) {
        return Err(PolicyError::WalletExists);
    }
    policy
        .wallets
        .insert(wallet.to_string(), WalletPolicy::new(chain));
    write_policy(policy_path, &policy)?;
    Ok(())
}

fn upsert_policy(policy_path: &Path, wallet: &str, chain: Chain) -> Result<(), PolicyError> {
    let mut policy = read_policy_or_default(policy_path)?;
    if policy.wallets.contains_key(wallet) {
        return Err(PolicyError::WalletExists);
    }
    policy
        .wallets
        .insert(wallet.to_string(), WalletPolicy::new(chain));
    write_policy(policy_path, &policy)?;
    Ok(())
}

fn read_policy(policy_path: &Path) -> Result<Policy, PolicyError> {
    let contents = fs::read_to_string(policy_path)?;
    if contents.trim().is_empty() {
        return Err(PolicyError::InvalidPolicy);
    }
    let policy = serde_yaml::from_str(&contents)?;
    Ok(policy)
}

fn read_policy_or_default(policy_path: &Path) -> Result<Policy, PolicyError> {
    if !policy_path.exists() {
        return Ok(Policy::default());
    }
    let contents = fs::read_to_string(policy_path)?;
    if contents.trim().is_empty() {
        return Ok(Policy::default());
    }
    let policy = serde_yaml::from_str(&contents)?;
    Ok(policy)
}

fn write_policy(policy_path: &Path, policy: &Policy) -> Result<(), PolicyError> {
    let out = serde_yaml::to_string(policy)?;
    fs::write(policy_path, out)?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), GenKeyError> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

pub mod cli {
    use std::fmt;
    use std::path::PathBuf;

    use crate::{
        add_wallet_stub, gen_key, install_layout, validate_policy, Chain, GenKeyError, InstallError,
        PolicyError,
    };

    #[derive(Debug)]
    pub enum CliError {
        MissingArg(&'static str),
        InvalidArg(String),
        GenKey(GenKeyError),
        Policy(PolicyError),
        Install(InstallError),
    }

    impl From<GenKeyError> for CliError {
        fn from(value: GenKeyError) -> Self {
            Self::GenKey(value)
        }
    }

    impl From<PolicyError> for CliError {
        fn from(value: PolicyError) -> Self {
            Self::Policy(value)
        }
    }

    impl From<InstallError> for CliError {
        fn from(value: InstallError) -> Self {
            Self::Install(value)
        }
    }

    impl fmt::Display for CliError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CliError::MissingArg(arg) => write!(f, "missing argument: {arg}"),
                CliError::InvalidArg(arg) => write!(f, "invalid argument: {arg}"),
                CliError::GenKey(err) => write!(f, "gen-key failed: {err:?}"),
                CliError::Policy(err) => write!(f, "policy failed: {err:?}"),
                CliError::Install(err) => write!(f, "install failed: {err:?}"),
            }
        }
    }

    pub fn run<I, S>(args: I) -> Result<String, CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut iter = args.into_iter();
        let cmd = iter
            .next()
            .ok_or(CliError::MissingArg("command"))?
            .as_ref()
            .to_string();

        match cmd.as_str() {
            "gen-key" => gen_key_cmd(iter),
            "policy" => policy_cmd(iter),
            "install" => install_cmd(iter),
            _ => Err(CliError::InvalidArg(format!("unknown command: {cmd}"))),
        }
    }

    fn gen_key_cmd<I, S>(mut iter: I) -> Result<String, CliError>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let mut chain: Option<Chain> = None;
        let mut wallet: Option<String> = None;
        let mut root: PathBuf = PathBuf::from("/opt/saw");

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
                "--chain" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--chain"))?
                        .as_ref()
                        .to_string();
                    chain = Some(parse_chain(&value)?);
                }
                "--wallet" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--wallet"))?
                        .as_ref()
                        .to_string();
                    wallet = Some(value);
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

        let chain = chain.ok_or(CliError::MissingArg("--chain"))?;
        let wallet = wallet.ok_or(CliError::MissingArg("--wallet"))?;

        let result = gen_key(chain, &wallet, &root)?;

        Ok(format!(
            "address: {}\npublic_key: {}\n",
            result.address, result.public_key
        ))
    }

    fn policy_cmd<I, S>(mut iter: I) -> Result<String, CliError>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let sub = iter
            .next()
            .ok_or(CliError::MissingArg("policy command"))?
            .as_ref()
            .to_string();

        match sub.as_str() {
            "validate" => policy_validate_cmd(iter),
            "add-wallet" => policy_add_wallet_cmd(iter),
            _ => Err(CliError::InvalidArg(format!("unknown policy command: {sub}"))),
        }
    }

    fn policy_validate_cmd<I, S>(mut iter: I) -> Result<String, CliError>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let mut root: PathBuf = PathBuf::from("/opt/saw");
        while let Some(arg) = iter.next() {
            match arg.as_ref() {
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

        let policy_path = root.join("policy.yaml");
        validate_policy(&policy_path)?;
        Ok("ok\n".to_string())
    }

    fn policy_add_wallet_cmd<I, S>(mut iter: I) -> Result<String, CliError>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let mut root: PathBuf = PathBuf::from("/opt/saw");
        let mut chain: Option<Chain> = None;
        let mut wallet: Option<String> = None;

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
                "--chain" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--chain"))?
                        .as_ref()
                        .to_string();
                    chain = Some(parse_chain(&value)?);
                }
                "--wallet" => {
                    let value = iter
                        .next()
                        .ok_or(CliError::MissingArg("--wallet"))?
                        .as_ref()
                        .to_string();
                    wallet = Some(value);
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

        let chain = chain.ok_or(CliError::MissingArg("--chain"))?;
        let wallet = wallet.ok_or(CliError::MissingArg("--wallet"))?;

        let policy_path = root.join("policy.yaml");
        add_wallet_stub(&policy_path, &wallet, chain)?;
        Ok("added\n".to_string())
    }

    fn install_cmd<I, S>(mut iter: I) -> Result<String, CliError>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let mut root: PathBuf = PathBuf::from("/opt/saw");

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
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

        install_layout(&root)?;
        Ok("installed\n".to_string())
    }

    fn parse_chain(value: &str) -> Result<Chain, CliError> {
        match value {
            "evm" => Ok(Chain::Evm),
            "sol" => Ok(Chain::Sol),
            _ => Err(CliError::InvalidArg(format!("chain: {value}"))),
        }
    }
}

pub fn install_layout(root: &Path) -> Result<(), InstallError> {
    fs::create_dir_all(root)?;
    set_mode_install(root, 0o750)?;

    let keys_dir = root.join("keys");
    fs::create_dir_all(&keys_dir)?;
    set_mode_install(&keys_dir, 0o700)?;

    let policy_path = root.join("policy.yaml");
    if !policy_path.exists() {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o640)
            .open(&policy_path)?;
        file.write_all(b"wallets:\n")?;
    }
    set_mode_install(&policy_path, 0o640)?;

    let audit_path = root.join("audit.log");
    if !audit_path.exists() {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o640)
            .open(&audit_path)?;
    }
    set_mode_install(&audit_path, 0o640)?;

    Ok(())
}

fn set_mode_install(path: &Path, mode: u32) -> Result<(), InstallError> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}
