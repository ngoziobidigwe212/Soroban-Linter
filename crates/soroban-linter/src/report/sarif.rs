use serde_json::{json, Value};

use crate::{all_rules, LintReport, Severity};

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Note => "note",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// SARIF 2.1.0, suitable for GitHub code scanning (`github/codeql-action/upload-sarif`).
pub fn render(report: &LintReport) -> String {
    let rules = all_rules();
    let rule_index = |id: &str| rules.iter().position(|r| r.info().id == id);

    let rule_descriptors: Vec<Value> = rules
        .iter()
        .map(|r| {
            let i = r.info();
            json!({
                "id": i.id,
                "name": i.name,
                "shortDescription": { "text": i.summary },
                "fullDescription": { "text": i.summary },
                "help": { "text": i.help },
                "defaultConfiguration": { "level": level(i.default_severity) },
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let uri = f.file.to_string_lossy().replace('\\', "/");
            let mut r = json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": f.line, "startColumn": f.column },
                    }
                }],
            });
            if let Some(i) = rule_index(f.rule_id) {
                r["ruleIndex"] = json!(i);
            }
            // Line-independent identity, so code scanning tracks alerts across edits.
            r["partialFingerprints"] =
                json!({ "sorobanLinterFinding/v1": crate::baseline::stable_hash(f) });
            r
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "soroban-linter",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": rule_descriptors,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).expect("JSON serialization cannot fail")
}
