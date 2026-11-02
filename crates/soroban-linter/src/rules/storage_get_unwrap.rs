use super::{FileContext, Rule, RuleInfo};
use crate::finding::{Finding, Severity};

pub struct StorageGetUnwrap;

static INFO: RuleInfo = RuleInfo {
    id: "SG007",
    name: "storage-get-unwrap",
    default_severity: Severity::Note,
    summary: "`storage.get(..)` result is unwrapped, giving an opaque panic when the entry is missing or expired",
    help: "Handle the missing case explicitly: `unwrap_or(default)`, or `unwrap_or_else(|| \
           panic_with_error!(&env, Error::NotInitialized))` so callers get a meaningful contract error.",
};

impl Rule for StorageGetUnwrap {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (_, facts) in &cx.fns {
            for &at in &facts.unwrapped_gets {
                out.push(cx.finding(
                    &INFO,
                    INFO.default_severity,
                    at,
                    "storage value is unwrapped; a missing or expired entry aborts with an opaque \
                     panic instead of a contract error",
                ));
            }
        }
    }
}
