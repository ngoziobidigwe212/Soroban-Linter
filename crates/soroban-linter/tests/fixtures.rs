//! Runs the linter on the fixture contracts and checks the findings line by line
//! against the `// expect: SGxxx` annotations.

use std::collections::BTreeSet;

use soroban_linter::{lint_source, LintConfig, LintReport};

fn lint_fixture(name: &str) -> (String, LintReport) {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(&path).unwrap();
    let report = lint_source(name, src.clone(), &LintConfig::default());
    assert!(report.parse_errors.is_empty(), "{:?}", report.parse_errors);
    (src, report)
}

fn expected(src: &str) -> BTreeSet<(usize, String)> {
    let mut out = BTreeSet::new();
    for (i, line) in src.lines().enumerate() {
        if let Some(pos) = line.find("// expect:") {
            let ids = line[pos + "// expect:".len()..].split(',').map(str::trim);
            for id in ids {
                let is_id = id.len() == 5
                    && id.starts_with("SG")
                    && id[2..].chars().all(|c| c.is_ascii_digit());
                if is_id {
                    out.insert((i + 1, id.to_string()));
                }
            }
        }
    }
    out
}

fn actual(report: &LintReport) -> BTreeSet<(usize, String)> {
    report
        .findings
        .iter()
        .map(|f| (f.line, f.rule_id.to_string()))
        .collect()
}

#[test]
fn vulnerable_contract_reports_every_planted_bug() {
    let (src, report) = lint_fixture("vulnerable_contract.rs");
    let expected = expected(&src);
    let actual = actual(&report);
    let missed: Vec<_> = expected.difference(&actual).collect();
    let unexpected: Vec<_> = actual.difference(&expected).collect();
    assert!(
        missed.is_empty() && unexpected.is_empty(),
        "missed: {missed:?}\nunexpected: {unexpected:?}\n\n{}",
        soroban_linter::report::text(&report)
    );
    // Every Rust-level rule is exercised by the fixture (SG009 is tested on manifests below).
    for rule in soroban_linter::all_rules()
        .into_iter()
        .filter(|r| r.info().id != "SG009")
    {
        assert!(
            expected.iter().any(|(_, id)| id == rule.info().id),
            "fixture has no case for {}",
            rule.info().id
        );
    }
}

#[test]
fn safe_contract_is_clean() {
    let (_, report) = lint_fixture("safe_contract.rs");
    assert!(
        report.findings.is_empty(),
        "{}",
        soroban_linter::report::text(&report)
    );
}

#[test]
fn loop_limit_is_configurable() {
    let path = format!(
        "{}/tests/fixtures/vulnerable_contract.rs",
        env!("CARGO_MANIFEST_DIR")
    );
    let src = std::fs::read_to_string(path).unwrap();
    let config = LintConfig {
        max_footprint_entries: 2000,
        max_write_entries: 2000,
        ..LintConfig::default()
    };
    let report = lint_source("v.rs", src, &config);
    // `sweep` (1000 entries) is now under the limit; the unbounded loops remain.
    let sg003 = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "SG003")
        .count();
    assert_eq!(sg003, 3);
}

#[test]
fn rules_can_be_disabled() {
    let path = format!(
        "{}/tests/fixtures/vulnerable_contract.rs",
        env!("CARGO_MANIFEST_DIR")
    );
    let src = std::fs::read_to_string(path).unwrap();
    let config = LintConfig {
        disabled: ["SG001".to_string(), "storage-get-unwrap".to_string()].into(),
        ..LintConfig::default()
    };
    let report = lint_source("v.rs", src, &config);
    assert!(report
        .findings
        .iter()
        .all(|f| f.rule_id != "SG001" && f.rule_id != "SG007"));
    assert!(!report.findings.is_empty());
}

fn lint_manifest_dir(dir: &str) -> Vec<(String, usize, String)> {
    let path = std::path::PathBuf::from(format!(
        "{}/tests/fixtures/manifests/{dir}",
        env!("CARGO_MANIFEST_DIR")
    ));
    let report = soroban_linter::lint_paths(&[path], &LintConfig::default()).unwrap();
    assert!(report.parse_errors.is_empty(), "{:?}", report.parse_errors);
    report
        .findings
        .iter()
        .map(|f| {
            let rel = f.file.to_string_lossy();
            let rel = rel.split("manifests/").nth(1).unwrap_or(&rel).to_string();
            (f.rule_id.to_string(), f.line, rel)
        })
        .collect()
}

#[test]
fn overflow_checks_missing() {
    assert_eq!(
        lint_manifest_dir("missing"),
        [("SG009".to_string(), 1, "missing/Cargo.toml".to_string())]
    );
}

#[test]
fn overflow_checks_disabled_in_workspace_root() {
    // Reported once, on the root manifest's `[profile.release]` line.
    assert_eq!(
        lint_manifest_dir("disabled_ws"),
        [("SG009".to_string(), 8, "disabled_ws/Cargo.toml".to_string())]
    );
}

#[test]
fn overflow_checks_enabled() {
    assert!(lint_manifest_dir("ok").is_empty());
}

#[test]
fn severity_override() {
    let path = format!(
        "{}/tests/fixtures/vulnerable_contract.rs",
        env!("CARGO_MANIFEST_DIR")
    );
    let src = std::fs::read_to_string(path).unwrap();
    let mut config = LintConfig::default();
    config
        .severity
        .insert("SG007", soroban_linter::Severity::Error);
    let report = lint_source("v.rs", src, &config);
    assert!(report
        .findings
        .iter()
        .filter(|f| f.rule_id == "SG007")
        .all(|f| f.severity == soroban_linter::Severity::Error));
}

/// Multi-crate fixture: a library with `#[contracttrait]` defaults, `Base::` calls,
/// same-named `storage.rs` modules and a generic `extend(key)` helper, plus an app crate.
#[test]
fn workspace_fixture_cross_crate_resolution() {
    let root = std::path::PathBuf::from(format!(
        "{}/tests/fixtures/workspace",
        env!("CARGO_MANIFEST_DIR")
    ));
    let report =
        soroban_linter::lint_paths(std::slice::from_ref(&root), &LintConfig::default()).unwrap();
    assert!(report.parse_errors.is_empty(), "{:?}", report.parse_errors);

    let mut expected = BTreeSet::new();
    for (path, src) in &report.sources {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        for (line, id) in self::expected(src) {
            expected.insert((rel.clone(), line, id));
        }
    }
    let actual: BTreeSet<_> = report
        .findings
        .iter()
        .map(|f| {
            let rel = f
                .file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            (rel, f.line, f.rule_id.to_string())
        })
        .collect();
    assert_eq!(
        expected,
        actual,
        "\n{}",
        soroban_linter::report::text(&report)
    );
}
