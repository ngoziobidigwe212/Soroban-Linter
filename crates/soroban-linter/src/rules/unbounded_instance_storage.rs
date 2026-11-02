use super::{FileContext, Rule, RuleInfo};
use crate::analysis::{StorageKind, StorageOp};
use crate::finding::{Finding, Severity};

pub struct UnboundedInstanceStorage;

static INFO: RuleInfo = RuleInfo {
    id: "SG006",
    name: "unbounded-instance-storage",
    default_severity: Severity::Warning,
    summary: "Per-user / per-id data stored in `instance()` storage",
    help: "All instance storage is a single ledger entry loaded on every invocation and has a hard size \
           limit. Keys like `DataKey::Balance(user)` grow without bound; store them in `persistent()` \
           storage instead and keep instance storage for small contract-wide configuration.",
};

impl Rule for UnboundedInstanceStorage {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (_, facts) in &cx.fns {
            for call in &facts.storage_calls {
                if call.kind == StorageKind::Instance
                    && call.op == StorageOp::Write
                    && call.key_is_parameterized
                {
                    let key = call.key.clone().unwrap_or_default().replace(' ', "");
                    out.push(cx.finding(
                        &INFO,
                        INFO.default_severity,
                        (call.line, call.column),
                        format!(
                            "`{key}` is a per-id key written to instance storage; the instance entry \
                             grows with every new id and is loaded on every call"
                        ),
                    ));
                }
            }
        }
    }
}
