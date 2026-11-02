use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;

use super::{FileContext, Rule, RuleInfo};
use crate::finding::{Finding, Severity};

pub struct UncheckedAuthAddress;

static INFO: RuleInfo = RuleInfo {
    id: "SG008",
    name: "unchecked-auth-address",
    default_severity: Severity::Error,
    summary: "`require_auth` is called on a caller-supplied address that is never checked against stored state",
    help: "`caller.require_auth()` only proves the transaction was signed by `caller`, and the caller \
           chooses that argument. For privileged actions, load the expected address from storage and \
           authorize it (`read_admin(&e).require_auth()`), or compare the argument with it before \
           authorizing.",
};

impl Rule for UncheckedAuthAddress {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in cx.entry_points() {
            let effects = cx.index.transitive(facts);
            if !(effects.mutates_storage || effects.upgrades) {
                continue;
            }
            let address_params = f.address_params();
            let params: Vec<String> = f.params().into_iter().map(|(p, _)| p).collect();

            // Overwriting the admin/owner while only caller-chosen addresses sign:
            // `set_admin(e, new_admin) { new_admin.require_auth(); write_admin(new_admin) }`.
            let name = f.name();
            if effects.writes_authority_key
                && cx
                    .index
                    .auth_only_on_unchecked_params(&f.key(), facts, &params)
            {
                let signers: Vec<String> = facts
                    .auth_targets
                    .iter()
                    .map(|(t, _)| format!("`{t}`"))
                    .collect();
                let (severity, extra) = if name.contains("init") {
                    (
                        Severity::Warning,
                        " Unless it runs atomically with deployment, it can be front-run; prefer `__constructor`.",
                    )
                } else {
                    (Severity::Error, "")
                };
                out.push(cx.finding(
                    &INFO,
                    severity,
                    f.line_col(),
                    format!(
                        "`{name}` overwrites an admin/owner-style key but only authorizes \
                         caller-supplied address(es) {}; anyone can call it signing as themselves \
                         and take control.{extra}",
                        signers.join(", ")
                    ),
                ));
                continue;
            }

            let body = f.block.to_token_stream();
            for (target, at) in &facts.auth_targets {
                if !address_params.contains(target) {
                    continue;
                }
                // The only use of the parameter is the `require_auth` call itself:
                // it is not compared, stored, or passed anywhere.
                if count_ident(body.clone(), target) == 1 {
                    out.push(cx.finding(
                        &INFO,
                        INFO.default_severity,
                        *at,
                        format!(
                            "`{target}.require_auth()` authorizes an address the caller chose, but \
                             `{target}` is never checked against an admin/owner or used otherwise; \
                             any account can pass its own address and pass this check"
                        ),
                    ));
                }
            }
        }
    }
}

fn count_ident(tokens: TokenStream, name: &str) -> usize {
    tokens
        .into_iter()
        .map(|tt| match tt {
            TokenTree::Ident(i) if i == name => 1,
            TokenTree::Group(g) => count_ident(g.stream(), name),
            _ => 0,
        })
        .sum()
}
