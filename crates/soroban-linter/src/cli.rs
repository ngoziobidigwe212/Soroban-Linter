//! Command-line interface shared by `soroban-linter` and `cargo soroban-linter`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::config::{FileConfig, LintConfig};
use crate::{all_rules, find_rule, lint_paths, report, Severity};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Note,
    Warning,
    Error,
    Never,
}

/// Static analysis for Soroban smart contracts.
#[derive(Debug, Parser)]
#[command(name = "soroban-linter", version, about)]
struct Cli {
    /// Files or directories to lint (`.rs` files and `Cargo.toml` manifests).
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Output format.
    #[arg(long, short, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Exit with status 1 if there is a finding at or above this severity [default: error].
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Config file [default: ./soroban-guard.toml if present].
    #[arg(long)]
    config: Option<PathBuf>,

    /// Rules to disable (ids or names, comma separated).
    #[arg(long, value_delimiter = ',')]
    disable: Vec<String>,

    /// Run only these rules (ids or names, comma separated).
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,

    /// Per-transaction footprint limit (ledger entries read + written) used by SG003
    /// [default: 400, Stellar mainnet].
    #[arg(long)]
    max_footprint_entries: Option<u128>,

    /// Per-transaction written-entry limit used by SG003 [default: 200, Stellar mainnet].
    #[arg(long)]
    max_write_entries: Option<u128>,

    /// Extra lower-case keywords that mark a storage key as critical state (SG001, SG002).
    #[arg(long, value_delimiter = ',')]
    critical_keyword: Vec<String>,

    /// Also lint `tests/` directories and `test.rs` files.
    #[arg(long)]
    include_tests: bool,

    /// List all rules and exit.
    #[arg(long)]
    list_rules: bool,

    /// Only report findings that are not in this baseline (a previous `--format json`
    /// report). Use it to adopt the linter on an existing codebase.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write the current findings as a baseline file and exit successfully.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// Explain a rule (id or name) and exit.
    #[arg(long, value_name = "RULE")]
    explain: Option<String>,
}

/// Runs the CLI and returns the process exit code
/// (0 = clean, 1 = findings at/above `--fail-on`, 2 = usage or I/O error).
pub fn run(args: impl IntoIterator<Item = OsString>) -> i32 {
    let mut args: Vec<OsString> = args.into_iter().collect();
    // `cargo soroban-linter ...` invokes us as `cargo-soroban-linter soroban-linter ...`.
    if args.get(1).is_some_and(|a| a == "soroban-linter") {
        args.remove(1);
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    match execute(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    }
}

fn execute(cli: Cli) -> anyhow::Result<i32> {
    if cli.list_rules {
        for r in all_rules() {
            let i = r.info();
            println!(
                "{}  {:<28} {:<8} {}",
                i.id, i.name, i.default_severity, i.summary
            );
        }
        return Ok(0);
    }
    if let Some(id) = &cli.explain {
        let rule = find_rule(id).ok_or_else(|| anyhow::anyhow!("unknown rule `{id}`"))?;
        let i = rule.info();
        println!(
            "{} {} ({})\n\n{}\n\nHow to fix:\n{}",
            i.id, i.name, i.default_severity, i.summary, i.help
        );
        let comment = if i.id == "SG009" { "#" } else { "//" };
        println!("\nSuppress with: {comment} soroban-guard: allow({})", i.id);
        return Ok(0);
    }

    // Defaults < config file < command line.
    let mut config = LintConfig::default();
    let config_path = cli.config.clone().or_else(FileConfig::discover);
    let file_config = match &config_path {
        Some(p) => FileConfig::load(p)?,
        None => FileConfig::default(),
    };
    config.apply_file(&file_config)?;

    for r in cli.disable.iter().chain(&cli.only) {
        if find_rule(r).is_none() {
            anyhow::bail!("unknown rule `{r}` (see --list-rules)");
        }
    }
    config.disabled.extend(cli.disable.iter().cloned());
    if !cli.only.is_empty() {
        config.only = Some(cli.only.iter().cloned().collect::<HashSet<_>>());
    }
    if let Some(n) = cli.max_footprint_entries {
        config.max_footprint_entries = n;
    }
    if let Some(n) = cli.max_write_entries {
        config.max_write_entries = n;
    }
    config
        .critical_keywords
        .extend(cli.critical_keyword.iter().map(|k| k.to_lowercase()));
    config.include_tests |= cli.include_tests;

    let fail_on = match (cli.fail_on, &file_config.fail_on) {
        (Some(f), _) => f,
        (None, Some(s)) => FailOn::from_str(s, true)
            .map_err(|_| anyhow::anyhow!("invalid `fail-on = \"{s}\"` in config"))?,
        (None, None) => FailOn::Error,
    };

    let mut report = lint_paths(&cli.paths, &config)?;

    if let Some(path) = &cli.write_baseline {
        std::fs::write(path, report::json(&report))?;
        eprintln!(
            "soroban-linter: wrote baseline with {} finding(s) to {}",
            report.findings.len(),
            path.display()
        );
        return Ok(0);
    }
    if let Some(path) = cli.baseline.as_ref().or(file_config.baseline.as_ref()) {
        let n = crate::baseline::apply(&mut report, path)?;
        if n > 0 {
            eprintln!("soroban-linter: {n} baselined finding(s) hidden");
        }
    }
    let rendered = match cli.format {
        Format::Text => report::text(&report),
        Format::Json => report::json(&report),
        Format::Sarif => report::sarif(&report),
    };
    match &cli.output {
        Some(path) => std::fs::write(path, rendered)?,
        None => print!("{rendered}"),
    }
    if cli.output.is_some() || !matches!(cli.format, Format::Text) {
        for (file, err) in &report.parse_errors {
            eprintln!("warning: could not parse {}: {err}", file.display());
        }
    }

    let threshold = match fail_on {
        FailOn::Note => Some(Severity::Note),
        FailOn::Warning => Some(Severity::Warning),
        FailOn::Error => Some(Severity::Error),
        FailOn::Never => None,
    };
    Ok(match threshold {
        Some(s) if report.has_findings_at_least(s) => 1,
        _ => 0,
    })
}
