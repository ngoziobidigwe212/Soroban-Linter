use super::{FileContext, Rule, RuleInfo};
use crate::analysis::short_variant;
use crate::finding::{Finding, Severity};

pub struct MissingTtlExtension;

static INFO: RuleInfo = RuleInfo {
    id: "SG005",
    name: "missing-ttl-extension",
    default_severity: Severity::Warning,
    summary: "Contract function writes persistent/temporary keys whose TTL is never extended",
    help: "New entries only get the network's minimum TTL. Call `extend_ttl(&key, threshold, extend_to)` \
           for every persistent/temporary key you write, either right after writing (typically in the \
           write helper) or whenever the key is read (extend-on-access), so data does not get archived \
           (persistent) or deleted (temporary) unexpectedly. Keys are matched by variant \
           (`DataKey::Balance(..)` -> `Balance`). A key counts as maintained if any code path \
           extends it, so extend-on-read designs are not reported.",
};

impl Rule for MissingTtlExtension {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, _) in cx.entry_points() {
            let keys = cx.index.ttl_keys(&f.key());
            // Keys extended on some other path (extend-on-read getters) are a
            // deliberate policy; report keys that are never extended anywhere.
            let missing: Vec<&str> = keys
                .unextended()
                .into_iter()
                .filter(|k| !cx.index.extended_anywhere(k))
                .collect();
            if missing.is_empty() {
                continue;
            }
            let list: Vec<String> = missing
                .iter()
                .map(|k| format!("`{}`", short_variant(k)))
                .collect();
            out.push(cx.finding(
                &INFO,
                INFO.default_severity,
                f.line_col(),
                format!(
                    "`{}` writes persistent/temporary key(s) {} whose TTL is never extended \
                     anywhere in the contract; they will expire after the minimum TTL",
                    f.name(),
                    list.join(", ")
                ),
            ));
        }
    }
}
