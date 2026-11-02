//! Output formats: human-readable text, JSON and SARIF 2.1.0.

mod sarif;
mod text;

use crate::LintReport;

pub use sarif::render as sarif;
pub use text::render as text;

pub fn json(report: &LintReport) -> String {
    let parse_errors: Vec<_> = report
        .parse_errors
        .iter()
        .map(|(file, error)| serde_json::json!({ "file": file, "error": error }))
        .collect();
    let value = serde_json::json!({
        "findings": report.findings,
        "parse_errors": parse_errors,
        "summary": {
            "files": report.sources.len(),
            "errors": report.count(crate::Severity::Error),
            "warnings": report.count(crate::Severity::Warning),
            "notes": report.count(crate::Severity::Note),
        }
    });
    serde_json::to_string_pretty(&value).expect("JSON serialization cannot fail")
}
