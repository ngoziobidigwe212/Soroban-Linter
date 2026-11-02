use std::fmt::Write;

use crate::{find_rule, LintReport, Severity};

/// rustc-style output with a source snippet and help text.
pub fn render(report: &LintReport) -> String {
    let mut out = String::new();
    for f in &report.findings {
        let _ = writeln!(
            out,
            "{}[{}] {}: {}",
            f.severity, f.rule_id, f.rule_name, f.message
        );
        let _ = writeln!(out, "  --> {}:{}:{}", f.file.display(), f.line, f.column);
        if let Some(src) = report
            .sources
            .get(&f.file)
            .and_then(|s| s.lines().nth(f.line.saturating_sub(1)))
        {
            let num = f.line.to_string();
            let pad = " ".repeat(num.len());
            let _ = writeln!(out, "{pad} |");
            let _ = writeln!(out, "{num} | {src}");
            let _ = writeln!(out, "{pad} | {}^", " ".repeat(f.column.saturating_sub(1)));
        }
        if let Some(rule) = find_rule(f.rule_id) {
            let _ = writeln!(out, "  = help: {}", rule.info().help);
        }
        out.push('\n');
    }
    for (file, err) in &report.parse_errors {
        let _ = writeln!(out, "warning: could not parse {}: {err}\n", file.display());
    }
    let _ = writeln!(
        out,
        "soroban-linter: {} file(s) checked, {} error(s), {} warning(s), {} note(s)",
        report.sources.len(),
        report.count(Severity::Error),
        report.count(Severity::Warning),
        report.count(Severity::Note),
    );
    out
}
