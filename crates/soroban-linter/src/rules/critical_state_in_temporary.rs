use super::{FileContext, Rule, RuleInfo};
use crate::analysis::{StorageKind, StorageOp};
use crate::finding::{Finding, Severity};

pub struct CriticalStateInTemporary;

static INFO: RuleInfo = RuleInfo {
    id: "SG002",
    name: "critical-state-in-temporary",
    default_severity: Severity::Error,
    summary: "Long-lived or valuable state (balances, owners, admins, ...) written to `temporary()` storage",
    help: "Temporary entries are permanently deleted when their TTL expires and cannot be restored. \
           Store balances, ownership and configuration in `persistent()` (per-key data) or `instance()` \
           (small contract-wide config) storage, and extend their TTL.",
};

/// Words that indicate data which is meant to expire.
const TEMPORARY_BY_DESIGN: &[&str] = &[
    "allowance",
    "approv",
    "nonce",
    "lock",
    "cache",
    "pending",
    "queue",
    "init",
    "check",
    "snapshot",
    "temp",
    "expir",
    "deadline",
];

impl Rule for CriticalStateInTemporary {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        let keywords = &cx.config.critical_keywords;
        for (f, facts) in &cx.fns {
            let fn_name = f.name().to_lowercase();
            for call in &facts.storage_calls {
                if call.kind != StorageKind::Temporary || call.op != StorageOp::Write {
                    continue;
                }
                let key = call.key.clone().unwrap_or_default();
                let key_lc = key.to_lowercase();
                // Short-lived by design: allowances, approvals, nonces, locks, queues, ...
                if TEMPORARY_BY_DESIGN
                    .iter()
                    .any(|w| key_lc.contains(w) || fn_name.contains(w))
                {
                    continue;
                }
                let hit = keywords
                    .iter()
                    .find(|k| key_lc.contains(k.as_str()))
                    .map(|k| (k, "key"))
                    .or_else(|| {
                        keywords
                            .iter()
                            .find(|k| fn_name.contains(k.as_str()))
                            .map(|k| (k, "function name"))
                    });
                if let Some((kw, source)) = hit {
                    let key = key.replace(' ', "");
                    out.push(cx.finding(
                        &INFO,
                        INFO.default_severity,
                        (call.line, call.column),
                        format!(
                            "`{key}` looks like critical state (\"{kw}\" in {source}) but is stored \
                             in temporary storage, which is deleted for good when its TTL expires"
                        ),
                    ));
                }
            }
        }
    }
}
