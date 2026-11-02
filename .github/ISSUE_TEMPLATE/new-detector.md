---
name: New detector rule
about: Propose a new soroban-linter rule
title: "Add detector: <rule-name>"
labels: ["linter", "new-rule", "good first issue"]
---

## Vulnerability pattern
What goes wrong, and why it is Soroban-specific.

## Vulnerable example
```rust
// minimal contract code that should be flagged
```

## Safe example
```rust
// equivalent code that must NOT be flagged
```

## Acceptance criteria
- [ ] Rule module in `crates/soroban-linter/src/rules/` with the next free `SGxxx` id
- [ ] Registered in `all_rules()`
- [ ] `// expect: SGxxx` case in `tests/fixtures/vulnerable_contract.rs`
- [ ] Safe counterpart in `tests/fixtures/safe_contract.rs` stays clean
- [ ] Row added to the rules table in `crates/soroban-linter/README.md`
