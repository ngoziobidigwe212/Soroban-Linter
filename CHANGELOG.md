# Changelog

## 0.1.0 (unreleased)

First release of `soroban-linter`.

- **Rules:** ten detectors.
  - SG001 missing auth (tiered by severity, with debit detection)
  - SG002 critical state in temporary storage
  - SG003 storage loops vs. network limits (400 footprint / 200 write entries, mainnet protocol 29)
  - SG004 unchecked `__check_auth`
  - SG005 per-key TTL maintenance
  - SG006 per-id keys in instance storage
  - SG007 unwrapped storage reads
  - SG008 unchecked or self-chosen authorizing addresses
  - SG009 `overflow-checks` disabled
  - SG010 unvalidated signed amounts
- **Cross-crate analysis:** full module paths, re-exported modules, `Type::f` calls, `#[contracttrait]` default methods, OpenZeppelin access-control attributes, and parameter-level facts (validated, authorized, debited, used as a storage key).
- **Output and CI:** text, JSON and SARIF (with stable fingerprints) output; baselines; `soroban-guard.toml`; `--explain`; GitHub Action.
- **Benchmark:** findings and mutation recall on five production codebases (`benchmarks/`).
