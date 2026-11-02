//! Inline suppressions.
//!
//! ```text
//! // soroban-guard: allow(SG001)                 on the line, or in the comment/attribute block above it
//! // soroban-guard: allow(SG001, storage-get-unwrap)
//! // soroban-guard: allow-file(SG007)            anywhere in the file
//! ```
//! `all` matches every rule.

const PREFIX: &str = "soroban-guard:";

pub fn is_suppressed(source: &str, line: usize, id: &str, name: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();

    if lines
        .iter()
        .any(|l| directive_matches(l, "allow-file", id, name))
    {
        return true;
    }

    let Some(idx) = line.checked_sub(1).filter(|&i| i < lines.len()) else {
        return false;
    };
    if directive_matches(lines[idx], "allow", id, name) {
        return true;
    }
    // Walk up through the comments / attributes directly above the line.
    for l in lines[..idx].iter().rev() {
        let t = l.trim_start();
        if !(t.starts_with("//") || t.starts_with("#[") || t.starts_with("#![")) {
            break;
        }
        if directive_matches(l, "allow", id, name) {
            return true;
        }
    }
    false
}

fn directive_matches(line: &str, kind: &str, id: &str, name: &str) -> bool {
    let Some(pos) = line.find(PREFIX) else {
        return false;
    };
    let rest = line[pos + PREFIX.len()..].trim_start();
    let Some(args) = rest
        .strip_prefix(kind)
        .and_then(|r| r.trim_start().strip_prefix('('))
    else {
        return false;
    };
    let args = args.split(')').next().unwrap_or("");
    args.split(',')
        .map(str::trim)
        .any(|a| a.eq_ignore_ascii_case(id) || a == name || a == "all")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_line_and_above() {
        let src = "// soroban-guard: allow(SG001)\n#[attr]\nfn a() {}\nfn b() {} // soroban-guard: allow(storage-get-unwrap)\n";
        assert!(is_suppressed(src, 3, "SG001", "missing-require-auth"));
        assert!(!is_suppressed(src, 3, "SG002", "x"));
        assert!(is_suppressed(src, 4, "SG007", "storage-get-unwrap"));
        assert!(!is_suppressed(src, 4, "SG001", "missing-require-auth"));
    }

    #[test]
    fn does_not_leak_past_code() {
        let src = "// soroban-guard: allow(SG001)\nfn a() {}\nfn b() {}\n";
        assert!(!is_suppressed(src, 3, "SG001", "missing-require-auth"));
    }

    #[test]
    fn file_level_and_all() {
        let src = "// soroban-guard: allow-file(all)\nfn a() {}\n";
        assert!(is_suppressed(src, 2, "SG005", "x"));
    }

    #[test]
    fn allow_does_not_match_allow_file() {
        let src = "fn a() {} // soroban-guard: allow-file(SG001)\n";
        // allow-file applies; plain `allow` parser must not misread it
        assert!(!directive_matches(src, "allow", "SG001", "x"));
    }
}
