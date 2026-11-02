use super::{FileContext, Rule, RuleInfo};
use crate::analysis::param_use;
use crate::finding::{Finding, Severity};

pub struct UnvalidatedAmount;

static INFO: RuleInfo = RuleInfo {
    id: "SG010",
    name: "unvalidated-amount",
    default_severity: Severity::Warning,
    summary: "Signed amount parameter (`i128`/`i64`) is used to change state without being range-checked",
    help: "Token amounts are signed in Soroban. A negative `amount` turns a debit into a credit \
           (e.g. `balance - amount`). Reject it before use: `if amount < 0 { panic_with_error!(..) }` \
           or a helper such as `check_nonnegative_amount(amount)`.",
};

impl Rule for UnvalidatedAmount {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in cx.entry_points() {
            let effects = cx.index.transitive(facts);
            // Constructor arguments come from the deployer, not from attackers.
            if !effects.mutates_storage || f.name() == "__constructor" {
                continue;
            }
            // Gated by a stored admin/owner: the value comes from a trusted caller.
            let params: Vec<String> = f.params().into_iter().map(|(p, _)| p).collect();
            let privileged = effects.requires_auth
                && !cx
                    .index
                    .auth_only_on_unchecked_params(&f.key(), facts, &params);
            let (severity, suffix) = if privileged {
                (Severity::Note, " (only callable by a privileged account)")
            } else {
                (INFO.default_severity, "")
            };
            for (i, (param, ty)) in f.params().into_iter().enumerate() {
                if param.starts_with('_') || !matches!(ty.as_str(), "i128" | "i64" | "i32") {
                    continue;
                }
                let used = param_use(f.block, &param).used;
                // Validated here, or in a crate helper the value is passed to.
                let validated = cx.index.validates_param(&f.key(), i);
                if used && !validated {
                    out.push(cx.finding(
                        &INFO,
                        severity,
                        f.line_col(),
                        format!(
                            "`{}` changes state using the signed parameter `{param}: {ty}` but never \
                             checks its range; a negative value can invert the intended effect{suffix}",
                            f.name()
                        ),
                    ));
                }
            }
        }
    }
}
