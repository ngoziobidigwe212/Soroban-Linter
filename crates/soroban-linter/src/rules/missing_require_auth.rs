use quote::ToTokens;

use super::{FileContext, Rule, RuleInfo};
use crate::analysis::mentions_ident;
use crate::finding::{Finding, Severity};

pub struct MissingRequireAuth;

static INFO: RuleInfo = RuleInfo {
    id: "SG001",
    name: "missing-require-auth",
    default_severity: Severity::Error,
    summary: "Public contract function changes state or upgrades the contract without calling `require_auth`",
    help: "Call `address.require_auth()` (or `require_auth_for_args`) for the account that is allowed to \
           perform this action, either directly or in a helper the function calls. One-time setup belongs \
           in `__constructor`, which runs atomically at deploy time and cannot be front-run. Severity: \
           error when anyone could upgrade the contract, overwrite an admin/owner-style key, or take \
           value from an address passed as an argument (e.g. `withdraw(from)`); warning \
           when the change is driven by a caller-supplied address or is an initializer; note for other \
           permissionless state changes (keepers, `distribute`, ...). Suppress reviewed cases with \
           `// soroban-guard: allow(SG001)`.",
};

impl Rule for MissingRequireAuth {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in cx.entry_points() {
            let name = f.name();
            // The constructor runs at deploy time; `__check_auth` is covered by SG004.
            if name == "__constructor" || name == "__check_auth" {
                continue;
            }
            let effects = cx.index.transitive(facts);
            if !(effects.upgrades || effects.mutates_storage) {
                continue;
            }

            // Addresses whose funds/rights this call takes away: (name, authorized?)
            let debited: Vec<(String, bool)> = f
                .params()
                .iter()
                .enumerate()
                .filter(|(i, (p, ty))| {
                    ty.split_whitespace().last() == Some("Address")
                        && !p.starts_with('_')
                        && cx.index.debits_param(&f.key(), *i)
                })
                .map(|(i, (p, _))| (p.clone(), cx.index.authorizes_param(&f.key(), i)))
                .collect();

            if effects.requires_auth {
                // Auth exists, but is it on the account that pays? Only judged when every
                // authorized address is caller-chosen; allowance flows and liquidations
                // legitimately debit someone other than the signer.
                let params: Vec<String> = f.params().into_iter().map(|(p, _)| p).collect();
                let by_design = effects.uses_allowance
                    || ["liquidat", "seize", "slash", "clawback"]
                        .iter()
                        .any(|w| name.contains(w));
                // Flag only when the signer pays nothing while someone else does.
                let signer_pays = debited.iter().any(|(_, authed)| *authed);
                if !by_design
                    && !signer_pays
                    && cx
                        .index
                        .auth_only_on_unchecked_params(&f.key(), facts, &params)
                {
                    if let Some((p, _)) = debited.iter().find(|(_, authed)| !authed) {
                        out.push(cx.finding(
                            &INFO,
                            Severity::Error,
                            f.line_col(),
                            format!(
                                "`{name}` takes value from `{p}` but only authorizes other \
                                 caller-supplied addresses; `{p}` never signs, so anyone can drain it"
                            ),
                        ));
                    }
                }
                continue;
            }
            let debited = debited.into_iter().next().map(|(p, _)| p);

            let body = f.block.to_token_stream();
            let caller_address = f
                .address_params()
                .into_iter()
                .find(|p| !p.starts_with('_') && mentions_ident(body.clone(), p));

            let (severity, message) = if effects.upgrades {
                (
                    Severity::Error,
                    format!(
                        "`{name}` can replace the contract code (`update_current_contract_wasm`) \
                         without any `require_auth` check; anyone can take over the contract"
                    ),
                )
            } else if name.contains("init") {
                (
                    Severity::Warning,
                    format!(
                        "`{name}` initializes contract state without `require_auth`; unless it is \
                         called atomically with deployment, anyone can front-run it. Prefer `__constructor`"
                    ),
                )
            } else if let Some(p) = debited {
                (
                    Severity::Error,
                    format!(
                        "`{name}` takes value from the caller-supplied address `{p}` (balance \
                         subtraction / spend) without `{p}.require_auth()`; anyone can drain any account"
                    ),
                )
            } else if effects.writes_authority_key {
                (
                    Severity::Error,
                    format!(
                        "`{name}` overwrites an admin/owner-style storage key without any \
                         `require_auth`; anyone can take control of the contract"
                    ),
                )
            } else if effects.reads_authority_key {
                (
                    Severity::Error,
                    format!(
                        "`{name}` loads an admin/owner-style key from storage but never calls \
                         `require_auth`; the privileged check appears to be missing"
                    ),
                )
            } else if let Some(p) = caller_address {
                (
                    Severity::Warning,
                    format!(
                        "`{name}` modifies contract storage based on the caller-supplied address \
                         `{p}` without `require_auth`; make sure `{p}` cannot lose funds or rights \
                         through this call"
                    ),
                )
            } else {
                (
                    Severity::Note,
                    format!(
                        "`{name}` is permissionless: it modifies contract storage without \
                         `require_auth`. Make sure anyone calling it at any time is intended"
                    ),
                )
            };
            out.push(cx.finding(&INFO, severity, f.line_col(), message));
        }
    }
}
