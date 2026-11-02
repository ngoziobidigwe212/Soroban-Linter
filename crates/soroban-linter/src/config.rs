//! Lint configuration, optionally loaded from `soroban-guard.toml`.
//!
//! ```toml
//! # soroban-guard.toml
//! max-footprint-entries = 400
//! max-write-entries = 200
//! critical-keywords = ["vault", "share"]   # added to the defaults
//! disable = ["SG007"]
//! include-tests = false
//! fail-on = "warning"
//!
//! [severity]
//! SG005 = "error"
//! storage-get-unwrap = "warning"
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

use crate::rules::{find_rule, RuleInfo};
use crate::Severity;

/// Default words that mark a storage key as holding critical, long-lived state.
pub const DEFAULT_CRITICAL_KEYWORDS: &[&str] = &[
    "balance",
    "owner",
    "admin",
    "supply",
    "deposit",
    "stake",
    "collateral",
    "debt",
    "reserve",
];

/// Per-transaction limits on Stellar mainnet, read from the network's
/// `CONFIG_SETTING_CONTRACT_LEDGER_COST_V0` / `_EXT_V0` entries
/// (protocol 29, November 2026). Check yours with `stellar network settings`.
pub const MAINNET_TX_MAX_FOOTPRINT_ENTRIES: u128 = 400;
pub const MAINNET_TX_MAX_WRITE_ENTRIES: u128 = 200;

/// Name of the config file looked up in the current directory.
pub const CONFIG_FILE_NAME: &str = "soroban-guard.toml";

#[derive(Debug, Clone)]
pub struct LintConfig {
    /// Per-transaction limit on ledger entries in the footprint (reads + writes), used by SG003.
    pub max_footprint_entries: u128,
    /// Per-transaction limit on written ledger entries, used by SG003.
    pub max_write_entries: u128,
    /// Lower-case words that mark a key as critical state (SG001, SG002).
    pub critical_keywords: Vec<String>,
    /// Rule ids or names to skip.
    pub disabled: HashSet<String>,
    /// If set, only these rule ids or names run.
    pub only: Option<HashSet<String>>,
    /// Severity overrides by rule id.
    pub severity: HashMap<&'static str, Severity>,
    /// Also lint `tests/` directories and `test.rs` files when walking directories.
    pub include_tests: bool,
}

impl Default for LintConfig {
    fn default() -> Self {
        LintConfig {
            max_footprint_entries: MAINNET_TX_MAX_FOOTPRINT_ENTRIES,
            max_write_entries: MAINNET_TX_MAX_WRITE_ENTRIES,
            critical_keywords: DEFAULT_CRITICAL_KEYWORDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            disabled: HashSet::new(),
            only: None,
            severity: HashMap::new(),
            include_tests: false,
        }
    }
}

impl LintConfig {
    pub fn is_enabled(&self, info: &RuleInfo) -> bool {
        let matches = |set: &HashSet<String>| {
            set.iter()
                .any(|s| s.eq_ignore_ascii_case(info.id) || s == info.name)
        };
        !matches(&self.disabled) && self.only.as_ref().map_or(true, matches)
    }

    /// Applies a config file on top of `self`.
    pub fn apply_file(&mut self, file: &FileConfig) -> anyhow::Result<()> {
        if let Some(n) = file.max_footprint_entries {
            self.max_footprint_entries = n.into();
        }
        if let Some(n) = file.max_write_entries {
            self.max_write_entries = n.into();
        }
        self.critical_keywords
            .extend(file.critical_keywords.iter().map(|k| k.to_lowercase()));
        for r in &file.disable {
            ensure_rule(r)?;
            self.disabled.insert(r.clone());
        }
        if let Some(only) = &file.only {
            for r in only {
                ensure_rule(r)?;
            }
            self.only = Some(only.iter().cloned().collect());
        }
        for (rule, sev) in &file.severity {
            self.severity.insert(ensure_rule(rule)?.id, *sev);
        }
        if let Some(t) = file.include_tests {
            self.include_tests = t;
        }
        Ok(())
    }
}

fn ensure_rule(r: &str) -> anyhow::Result<&'static RuleInfo> {
    find_rule(r)
        .map(|r| r.info())
        .ok_or_else(|| anyhow::anyhow!("unknown rule `{r}` (see --list-rules)"))
}

/// Contents of `soroban-guard.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileConfig {
    pub max_footprint_entries: Option<u64>,
    pub max_write_entries: Option<u64>,
    #[serde(default)]
    pub critical_keywords: Vec<String>,
    #[serde(default)]
    pub disable: Vec<String>,
    pub only: Option<Vec<String>>,
    pub include_tests: Option<bool>,
    /// `error`, `warning`, `note` or `never`; used by the CLI.
    pub fail_on: Option<String>,
    /// Baseline file of accepted findings; used by the CLI.
    pub baseline: Option<PathBuf>,
    #[serde(default)]
    pub severity: HashMap<String, Severity>,
}

impl FileConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    /// `soroban-guard.toml` in the current directory, if any.
    pub fn discover() -> Option<PathBuf> {
        let p = PathBuf::from(CONFIG_FILE_NAME);
        p.is_file().then_some(p)
    }
}
