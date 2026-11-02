use super::{FileContext, Rule, RuleInfo};
use crate::finding::{Finding, Severity};
use crate::manifest::ManifestSet;

pub struct OverflowChecks;

static INFO: RuleInfo = RuleInfo {
    id: "SG009",
    name: "overflow-checks-disabled",
    default_severity: Severity::Error,
    summary: "Contract crate is built without `overflow-checks = true` in the release profile",
    help:
        "Release builds wrap on integer overflow by default, so `balance + amount` on `i128` can \
           silently wrap around instead of failing. Add `[profile.release]` with \
           `overflow-checks = true` to the workspace root `Cargo.toml` (profiles in member crates \
           are ignored by Cargo).",
};

impl Rule for OverflowChecks {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, _cx: &FileContext<'_>, _out: &mut Vec<Finding>) {}

    fn check_manifests(&self, set: &ManifestSet, out: &mut Vec<Finding>) {
        for (root, crates) in set.roots() {
            if root.release_overflow_checks() == Some(true) {
                continue;
            }
            let names: Vec<String> = crates
                .iter()
                .filter_map(|c| c.table.get("package")?.get("name")?.as_str())
                .map(|n| format!("`{n}`"))
                .collect();
            let what = match root.release_overflow_checks() {
                Some(false) => "sets `overflow-checks = false`",
                _ => "does not enable `overflow-checks`",
            };
            let line = root.line_of_section("[profile.release]").unwrap_or(1);
            out.push(Finding {
                rule_id: INFO.id,
                rule_name: INFO.name,
                severity: INFO.default_severity,
                message: format!(
                    "the release profile {what}; integer arithmetic in contract crate(s) {} will \
                     wrap silently on overflow",
                    names.join(", ")
                ),
                file: root.path.clone(),
                line,
                column: 1,
            });
        }
    }
}
