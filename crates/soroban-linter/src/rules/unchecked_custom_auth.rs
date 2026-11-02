use quote::ToTokens;
use syn::{FnArg, Pat};

use super::{FileContext, Rule, RuleInfo};
use crate::analysis::mentions_ident;
use crate::finding::{Finding, Severity};

pub struct UncheckedCustomAuth;

static INFO: RuleInfo = RuleInfo {
    id: "SG004",
    name: "unchecked-custom-auth",
    default_severity: Severity::Error,
    summary: "Custom account `__check_auth` does not verify signatures against the signature payload",
    help: "`__check_auth` decides whether *any* action on behalf of this account is authorized. It must \
           verify each signature over `signature_payload` (e.g. `env.crypto().ed25519_verify(..)`) or \
           delegate to other accounts with `require_auth`, and should check `auth_contexts`.",
};

impl Rule for UncheckedCustomAuth {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in &cx.fns {
            if f.name() != "__check_auth" {
                continue;
            }
            let effects = cx.index.transitive(facts);
            let mut problems = Vec::new();
            // Delegating to other accounts means they check the payload instead.
            let delegates = effects.requires_auth || effects.delegates_auth;
            if !effects.verifies_signature && !delegates {
                problems.push(
                    "never verifies a signature (no `ed25519_verify`/`secp256r1_verify`/\
                     `secp256k1_recover`/`pairing_check`) or delegates to other accounts"
                        .to_string(),
                );
            }
            if let Some(payload) = payload_param(f.sig).filter(|_| !delegates) {
                if payload.starts_with('_') || !mentions_ident(f.block.to_token_stream(), &payload)
                {
                    problems.push(format!("ignores the signature payload `{payload}`"));
                }
            }
            if !problems.is_empty() {
                out.push(cx.finding(
                    &INFO,
                    INFO.default_severity,
                    f.line_col(),
                    format!(
                        "`__check_auth` {}; any signature would be accepted",
                        problems.join(" and ")
                    ),
                ));
            }
        }
    }
}

/// Name of the `signature_payload` parameter (the 2nd argument by convention).
fn payload_param(sig: &syn::Signature) -> Option<String> {
    let names: Vec<String> = sig
        .inputs
        .iter()
        .filter_map(|a| match a {
            FnArg::Typed(t) => match &*t.pat {
                Pat::Ident(p) => Some(p.ident.to_string()),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect();
    names
        .iter()
        .find(|n| n.contains("payload"))
        .or_else(|| names.get(1))
        .cloned()
}
