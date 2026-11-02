# Contributing

Thanks for helping make Soroban contracts safer!

## Setup

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

CI runs the same commands.

## Adding a detector rule

Each rule is a single file in `crates/soroban-linter/src/rules/`.

1. **Copy a similar rule.** `storage_get_unwrap.rs` is the smallest. `missing_require_auth.rs` shows how to use the crate-wide call graph.
2. **Pick the next free id** (`SG011`, …) and a kebab-case name. Fill in the `RuleInfo`: `summary` is one line, and `help` says how to fix the problem.
3. **Register it** in `all_rules()` in `rules/mod.rs`.
4. **Add test cases:**
   - In `tests/fixtures/vulnerable_contract.rs`, add code that should be flagged and put `// expect: SG011` on the line the finding points to.
   - In `tests/fixtures/safe_contract.rs`, add the correct version of the pattern. This file must stay free of findings.
5. **Document it** with a row in the rules table in `crates/soroban-linter/README.md`.

What rules get to work with (`FileContext`):

| Field | What it gives you |
|---|---|
| `cx.fns` | Every non-test function with its `FnFacts`: storage calls (kind, op, key text, location), callees, auth/upgrade/signature flags |
| `cx.entry_points()` | Only the functions exported by `#[contractimpl]` |
| `cx.index.transitive(&facts)` | `Effects` including everything the function calls (auth, mutation, TTL extension, …) |
| `cx.index.consts` | Integer constants of the crate, for bounds |
| `f.block` / `f.sig` | The raw `syn` AST, if you need to write your own visitor |
| `cx.index.validates_param(name, i)` | Whether parameter `i` is range-checked, here or in a helper |
| `f.params()`, `f.address_params()` | Typed parameters of a function |
| `cx.config` | User configuration |
| `Rule::check_manifests` | Optional hook for `Cargo.toml` checks (see `overflow_checks.rs`) |

Before opening a PR, run the benchmark and look at every new finding:

```bash
cargo build --release
python3 benchmarks/run.py --linter target/release/soroban-linter --cache /tmp/sg-corpus --skip-mutation
```

A new **error** on these audited codebases is almost always a false positive. Turn each false positive you fix into a case in `safe_contract.rs`, or in `tests/fixtures/workspace/` if it involves several modules or crates. If your change affects auth or TTL detection, run the full benchmark (without `--skip-mutation`) and include the recall numbers in the PR.

Keep rules **precise rather than noisy**. A finding should point at something a reviewer would want to look at. When in doubt, start with `Severity::Note` or `Warning`.

## Good first issues

Look for issues labeled `good first issue` / `new-rule`. Please comment on an issue before starting so work isn't duplicated.
