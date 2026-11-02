//! # soroban-linter
//!
//! Static analysis for [Soroban](https://soroban.stellar.org) smart contracts.
//! It parses contract source with `syn` (no nightly toolchain, no compilation)
//! and runs a set of detector rules looking for auth, storage-lifecycle and
//! resource-limit bugs. See [`rules::all_rules`] for the list.
//!
//! ```
//! use soroban_linter::{lint_source, LintConfig};
//!
//! let src = r#"
//!     #[contractimpl]
//!     impl Vault {
//!         pub fn set_admin(e: Env, admin: Address) {
//!             e.storage().instance().set(&DataKey::Admin, &admin);
//!         }
//!     }
//! "#;
//! let report = lint_source("lib.rs", src, &LintConfig::default());
//! assert_eq!(report.findings[0].rule_id, "SG001");
//! ```

#![forbid(unsafe_code)]

pub mod analysis;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod finding;
pub mod manifest;
pub mod report;
pub mod rules;
mod suppress;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;

use analysis::CrateIndex;
pub use config::{FileConfig, LintConfig, DEFAULT_CRITICAL_KEYWORDS};
pub use finding::{Finding, Severity};
pub use rules::{all_rules, find_rule, FileContext, Rule, RuleInfo};

/// An input file: Rust source, or a `Cargo.toml` manifest.
pub struct SourceFile {
    pub path: PathBuf,
    pub source: String,
}

impl SourceFile {
    fn is_manifest(&self) -> bool {
        self.path.file_name().is_some_and(|n| n == "Cargo.toml")
    }
}

#[derive(Debug, Default)]
pub struct LintReport {
    /// Sorted by file, line, column.
    pub findings: Vec<Finding>,
    /// Files that could not be parsed, with the error.
    pub parse_errors: Vec<(PathBuf, String)>,
    /// Source of every linted file (used for snippets).
    pub sources: BTreeMap<PathBuf, String>,
}

impl LintReport {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    pub fn has_findings_at_least(&self, severity: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= severity)
    }
}

/// Lints a single in-memory source file.
pub fn lint_source(
    path: impl Into<PathBuf>,
    source: impl Into<String>,
    config: &LintConfig,
) -> LintReport {
    lint_sources(
        vec![SourceFile {
            path: path.into(),
            source: source.into(),
        }],
        config,
    )
}

/// Lints a set of files together; calls between Rust files are resolved as one crate.
pub fn lint_sources(files: Vec<SourceFile>, config: &LintConfig) -> LintReport {
    let mut report = LintReport::default();
    let rules: Vec<_> = all_rules()
        .into_iter()
        .filter(|r| config.is_enabled(r.info()))
        .collect();

    let (manifests, rust) = split_manifests(files);

    let mut parsed = Vec::new();
    for file in rust {
        match syn::parse_file(&file.source) {
            Ok(ast) => parsed.push((file, ast)),
            Err(e) => {
                let at = e.span().start();
                report
                    .parse_errors
                    .push((file.path, format!("{}:{}: {e}", at.line, at.column + 1)));
            }
        }
    }

    let mut found = Vec::new();

    let index = CrateIndex::build(parsed.iter().map(|(f, ast)| (f.path.as_path(), ast)));
    for (file, ast) in &parsed {
        let cx = FileContext::new(&file.path, &file.source, ast, &index, config);
        for rule in &rules {
            rule.check(&cx, &mut found);
        }
    }

    let manifest_set = manifest::ManifestSet::parse(&manifests, &mut report.parse_errors);
    for rule in &rules {
        rule.check_manifests(&manifest_set, &mut found);
    }

    for f in parsed
        .into_iter()
        .map(|(f, _)| f)
        .chain(manifests)
        .chain(manifest_set.extra_sources())
    {
        report.sources.entry(f.path).or_insert(f.source);
    }

    for f in &mut found {
        if let Some(sev) = config.severity.get(f.rule_id) {
            f.severity = *sev;
        }
    }
    found.retain(|f| {
        !report
            .sources
            .get(&f.file)
            .is_some_and(|src| suppress::is_suppressed(src, f.line, f.rule_id, f.rule_name))
    });
    found.sort_by(|a, b| {
        (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id))
    });
    found.dedup();
    report.findings = found;
    report
}

/// Returns `(manifests, rust sources)`.
fn split_manifests(files: Vec<SourceFile>) -> (Vec<SourceFile>, Vec<SourceFile>) {
    files.into_iter().partition(SourceFile::is_manifest)
}

/// Recursively collects `.rs` files and `Cargo.toml` manifests, skipping `target/`,
/// hidden directories and (unless `include_tests`) test code.
/// Explicitly named files are always included.
pub fn collect_files(paths: &[PathBuf], include_tests: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for root in paths {
        if root.is_file() {
            out.push(root.clone());
            continue;
        }
        if !root.exists() {
            anyhow::bail!("path does not exist: {}", root.display());
        }
        let walker = walkdir::WalkDir::new(root).sort_by_file_name();
        for entry in walker.into_iter().filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            let is_dir = e.file_type().is_dir();
            !(name.starts_with('.')
                || (is_dir && matches!(name.as_ref(), "target" | "node_modules"))
                || (!include_tests && is_test_path(&name, is_dir)))
        }) {
            let entry = entry?;
            let p = entry.path();
            let wanted = p.extension().is_some_and(|x| x == "rs")
                || p.file_name().is_some_and(|n| n == "Cargo.toml");
            if entry.file_type().is_file() && wanted {
                out.push(clean_path(p));
            }
        }
    }
    Ok(out)
}

fn is_test_path(name: &str, is_dir: bool) -> bool {
    if is_dir {
        matches!(name, "tests" | "test" | "benches" | "test_snapshots")
    } else {
        matches!(name, "test.rs" | "tests.rs") || name.ends_with("_test.rs")
    }
}

fn clean_path(p: &Path) -> PathBuf {
    p.strip_prefix(".")
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| p.to_path_buf())
}

/// Collects and lints every `.rs` file and `Cargo.toml` under `paths`.
pub fn lint_paths(paths: &[PathBuf], config: &LintConfig) -> anyhow::Result<LintReport> {
    let files = collect_files(paths, config.include_tests)?
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Ok(SourceFile { path, source })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(lint_sources(files, config))
}
