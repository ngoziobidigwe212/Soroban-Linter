#!/usr/bin/env python3
"""Reproducible benchmark for soroban-linter on real Soroban codebases.

1. Findings: lints each repo in `corpus.txt` (pinned commits) and counts findings
   by rule and severity. Every *error* should be a real problem.
2. Mutation recall: removes one security-relevant statement at a time from the real
   code and checks that the linter reports something new.
     auth  remove one `x.require_auth()` / `require_auth_for_args(..)`  (SG001, SG008)
     ttl   remove one persistent/temporary `.extend_ttl(..)`            (SG005)
           (often equivalent: many keys are extended both on read and on write)
     ttl-file  remove every persistent/temporary `.extend_ttl(..)` of one file (SG005)

Usage:
    cargo build --release
    python3 benchmarks/run.py --linter target/release/soroban-linter --cache /tmp/sg-corpus
"""
import argparse, collections, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AUTH = re.compile(r'^\s*[A-Za-z_][\w.()&]*\.require_auth(_for_args)?\(.*\);\s*(//.*)?$')


def statement_at(lines, i):
    """Line span (start, end) of the statement containing line `i`."""
    start = i
    while start > 0 and not lines[start - 1].rstrip().endswith((";", "{", "}")):
        start -= 1
    end = i
    while end < len(lines) - 1 and not lines[end].split("//")[0].rstrip().endswith(";"):
        end += 1
    return start, end


def auth_sites(lines):
    return [(i, i) for i, l in enumerate(lines) if AUTH.match(l)]


def ttl_sites(lines):
    """`<storage>.persistent()/.temporary().extend_ttl(..);` statements, possibly multi-line."""
    out = []
    for i, l in enumerate(lines):
        if ".extend_ttl(" not in l:
            continue
        start, end = statement_at(lines, i)
        text = " ".join(x.strip() for x in lines[start:end + 1])
        if "storage()" in text and re.search(r"\.(persistent|temporary)\(\)", text) \
                and text.endswith(";") and not text.startswith(("let ", "//", "///")):
            out.append((start, end))
    return out


def ttl_file(lines):
    """All TTL extensions of a file at once (a module that forgot TTL management)."""
    sites = ttl_sites(lines)
    return [sites] if sites else []


# op -> (mutants of a file: list of lists of (start, end) spans to delete, rules)
OPS = {
    "auth": (lambda lines: [[s] for s in auth_sites(lines)], "SG001,SG008"),
    "ttl": (lambda lines: [[s] for s in ttl_sites(lines)], "SG005"),
    "ttl-file": (ttl_file, "SG005"),
}


def corpus():
    with open(os.path.join(HERE, "corpus.txt")) as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                yield line.split()


def checkout(cache, name, url, commit):
    dest = os.path.join(cache, name)
    if not os.path.isdir(dest):
        subprocess.run(["git", "clone", "-q", url, dest], check=True)
    subprocess.run(["git", "-C", dest, "checkout", "-q", commit], check=True)
    return dest


def lint(linter, path, only=None):
    cmd = [linter, path, "--fail-on", "never", "-f", "json"]
    if only:
        cmd += ["--only", only]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)


def mutation(linter, root, op):
    sites_of, rules = OPS[op]

    def keyset(path):
        return collections.Counter(
            (os.path.relpath(f["file"], path), f["rule_id"], f["message"])
            for f in lint(linter, path, rules)["findings"] if f["severity"] != "note")

    base = keyset(root)
    total = detected = 0
    missed = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ("target", "test", "tests") and not d.startswith(".")]
        for name in fn:
            if not name.endswith(".rs") or name in ("test.rs", "tests.rs"):
                continue
            path = os.path.join(dp, name)
            lines = open(path, encoding="utf-8").read().split("\n")
            for spans in sites_of(lines):
                drop = {i for start, end in spans for i in range(start, end + 1)}
                start, end = spans[0]
                tmp = tempfile.mkdtemp()
                try:
                    copy = os.path.join(tmp, "repo")
                    shutil.copytree(root, copy, ignore=shutil.ignore_patterns("target", ".git"))
                    with open(os.path.join(copy, os.path.relpath(path, root)), "w") as f:
                        f.write("\n".join(l for j, l in enumerate(lines) if j not in drop))
                    total += 1
                    if keyset(copy) - base:
                        detected += 1
                    else:
                        missed.append(f"{os.path.relpath(path, root)}:{start + 1}: {lines[end].strip()}")
                finally:
                    shutil.rmtree(tmp)
    return total, detected, missed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--linter", required=True)
    ap.add_argument("--cache", required=True, help="directory for cloned repositories")
    ap.add_argument("--skip-mutation", action="store_true")
    ap.add_argument("--show-missed", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.cache, exist_ok=True)

    print("## Findings\n")
    print("| repo | files | errors | warnings | notes |\n|---|---|---|---|---|")
    repos = []
    for name, url, commit in corpus():
        path = checkout(args.cache, name, url, commit)
        repos.append((name, path))
        s = lint(args.linter, path)["summary"]
        print(f"| {name} | {s['files']} | {s['errors']} | {s['warnings']} | {s['notes']} |")
    if args.skip_mutation:
        return
    for op in OPS:
        print(f"\n## Mutation recall: {op}\n")
        print("| repo | mutants | detected | rate |\n|---|---|---|---|")
        tt = td = 0
        for name, path in repos:
            t, d, missed = mutation(args.linter, path, op)
            tt += t
            td += d
            print(f"| {name} | {t} | {d} | {100 * d / max(t, 1):.1f}% |")
            if args.show_missed:
                for m in missed:
                    print(f"  missed: {name}/{m}", file=sys.stderr)
        print(f"| **total** | {tt} | {td} | **{100 * td / max(tt, 1):.1f}%** |")


if __name__ == "__main__":
    main()
