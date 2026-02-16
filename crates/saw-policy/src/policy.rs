//! Policy engine: evaluates signing requests against configurable rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use saw_mpc::protocol::{Decision, PolicyDecision, SignRequest, TxDetails};

/// Top-level policy configuration, loaded from policy.yaml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub wallets: HashMap<String, WalletPolicy>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_action")]
    pub action: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            action: default_action(),
        }
    }
}

fn default_action() -> String {
    "escalate".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicy {
    pub chain: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub circuit_breakers: Vec<CircuitBreaker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub action: String,
    #[serde(default)]
    pub conditions: RuleConditions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConditions {
    pub max_value_usd: Option<f64>,
    pub allowed_chains: Option<Vec<u64>>,
    pub allowed_contracts: Option<Vec<String>>,
    pub allowlist_recipients: Option<Vec<String>>,
    pub max_daily_spend_usd: Option<f64>,
    pub max_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub name: String,
    pub condition: String,
    pub action: String,
    #[serde(default)]
    pub cooldown_hours: Option<u32>,
}

/// Runtime state for policy evaluation (spend tracking, rate limits).
pub struct PolicyState {
    /// Spend tracking per wallet: (amount_usd, timestamp)
    daily_spend: HashMap<String, Vec<(f64, Instant)>>,
    /// Rate tracking per wallet: timestamps of recent requests
    rate_history: HashMap<String, Vec<Instant>>,
    /// Tripped circuit breakers: wallet → (breaker name, tripped at)
    tripped_breakers: HashMap<String, (String, Instant)>,
}

impl PolicyState {
    pub fn new() -> Self {
        Self {
            daily_spend: HashMap::new(),
            rate_history: HashMap::new(),
            tripped_breakers: HashMap::new(),
        }
    }
}

/// Evaluate a signing request against the policy.
pub fn evaluate(
    config: &PolicyConfig,
    state: &mut PolicyState,
    request: &SignRequest,
) -> PolicyDecision {
    let wallet_policy = match config.wallets.get(&request.wallet) {
        Some(wp) => wp,
        None => {
            return PolicyDecision {
                request_id: request.request_id.clone(),
                decision: parse_decision(&config.defaults.action),
                matched_rule: None,
                reason: Some("wallet not in policy".into()),
            };
        }
    };

    // Check circuit breakers first
    if let Some((breaker_name, _)) = state.tripped_breakers.get(&request.wallet) {
        return PolicyDecision {
            request_id: request.request_id.clone(),
            decision: Decision::Deny,
            matched_rule: Some(breaker_name.clone()),
            reason: Some("circuit breaker tripped".into()),
        };
    }

    // Evaluate rules top-to-bottom, first match wins
    for rule in &wallet_policy.rules {
        if matches_rule(rule, &request.tx_details, state, &request.wallet) {
            return PolicyDecision {
                request_id: request.request_id.clone(),
                decision: parse_decision(&rule.action),
                matched_rule: Some(rule.name.clone()),
                reason: None,
            };
        }
    }

    // No rule matched — use default
    PolicyDecision {
        request_id: request.request_id.clone(),
        decision: parse_decision(&config.defaults.action),
        matched_rule: None,
        reason: Some("no matching rule".into()),
    }
}

fn matches_rule(
    rule: &Rule,
    tx: &TxDetails,
    state: &PolicyState,
    wallet: &str,
) -> bool {
    // Check chain allowlist
    if let Some(allowed_chains) = &rule.conditions.allowed_chains {
        if let Some(chain_id) = tx.chain_id {
            if !allowed_chains.contains(&chain_id) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Check recipient allowlist
    if let Some(allowlist) = &rule.conditions.allowlist_recipients {
        if let Some(to) = &tx.to {
            let to_lower = to.to_lowercase();
            if !allowlist.iter().any(|a| a.to_lowercase() == to_lower) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Check contract allowlist
    if let Some(allowed_contracts) = &rule.conditions.allowed_contracts {
        if let Some(to) = &tx.to {
            let to_lower = to.to_lowercase();
            if !allowed_contracts.iter().any(|a| a.to_lowercase() == to_lower) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Deny if unimplemented spend-limit conditions are set, rather than
    // silently matching all transactions.
    if rule.conditions.max_value_usd.is_some() {
        tracing::warn!("max_value_usd condition is not yet implemented — denying to be safe");
        return false;
    }
    if rule.conditions.max_daily_spend_usd.is_some() {
        tracing::warn!("max_daily_spend_usd condition is not yet implemented — denying to be safe");
        return false;
    }
    if rule.conditions.max_per_minute.is_some() {
        tracing::warn!("max_per_minute condition is not yet implemented — denying to be safe");
        return false;
    }

    // If we got here, all specified conditions are met
    true
}

fn parse_decision(action: &str) -> Decision {
    match action {
        "approve" => Decision::Approve,
        "deny" => Decision::Deny,
        _ => Decision::Escalate,
    }
}
