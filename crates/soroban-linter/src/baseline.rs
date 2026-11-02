//! Baselines: accept the findings that exist today and report only new ones.
//!
//! A baseline is a JSON report (`--format json`). Findings are matched on
//! `(rule, file, message)`, not on line numbers, so unrelated edits that move code
//! around do not resurface baselined findings.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;

use crate::{Finding, LintReport};

type Fingerprint = (String, String, String);

fn fingerprint(rule_id: &str, file: &str, message: &str) -> Fingerprint {
    (
        rule_id.to_string(),
        file.replace('\\', "/"),
        message.to_string(),
    )
}

fn of(f: &Finding) -> Fingerprint {
    fingerprint(f.rule_id, &f.file.to_string_lossy(), &f.message)
}

/// Removes findings present in the baseline file; returns how many were removed.
pub fn apply(report: &mut LintReport, baseline: &Path) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(baseline)
        .with_context(|| format!("failed to read baseline {}", baseline.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("baseline {} is not a JSON report", baseline.display()))?;
    let entries = json["findings"]
        .as_array()
        .with_context(|| format!("baseline {} has no `findings` array", baseline.display()))?;

    let mut known: HashMap<Fingerprint, usize> = HashMap::new();
    for e in entries {
        let get = |k: &str| e[k].as_str().unwrap_or_default();
        *known
            .entry(fingerprint(get("rule_id"), get("file"), get("message")))
            .or_default() += 1;
    }

    let before = report.findings.len();
    report.findings.retain(|f| match known.get_mut(&of(f)) {
        Some(n) if *n > 0 => {
            *n -= 1;
            false
        }
        _ => true,
    });
    Ok(before - report.findings.len())
}

/// Stable identifier of a finding for SARIF `partialFingerprints` (FNV-1a, 64 bit).
pub fn stable_hash(f: &Finding) -> String {
    let (rule, file, message) = of(f);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in [rule, file, message].join("\u{0}").bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}
