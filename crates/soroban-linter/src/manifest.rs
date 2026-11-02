//! `Cargo.toml` handling: finds Soroban contract crates and the workspace
//! root whose `[profile.*]` settings apply to them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::SourceFile;

pub struct Manifest {
    pub path: PathBuf,
    pub source: String,
    pub table: toml::Table,
}

impl Manifest {
    fn parse(path: PathBuf, source: String) -> Result<Self, String> {
        let table = source.parse::<toml::Table>().map_err(|e| e.to_string())?;
        Ok(Manifest {
            path,
            source,
            table,
        })
    }

    fn get(&self, keys: &[&str]) -> Option<&toml::Value> {
        let (first, rest) = keys.split_first()?;
        rest.iter()
            .try_fold(self.table.get(*first)?, |v, k| v.get(*k))
    }

    pub fn is_workspace_root(&self) -> bool {
        self.table.contains_key("workspace")
    }

    /// A crate that depends on `soroban-sdk` and builds a `cdylib` (i.e. a contract).
    pub fn is_contract_crate(&self) -> bool {
        let sdk = self
            .get(&["dependencies"])
            .and_then(|d| d.as_table())
            .is_some_and(|d| d.contains_key("soroban-sdk"));
        let cdylib = self
            .get(&["lib", "crate-type"])
            .and_then(|t| t.as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("cdylib")));
        sdk && cdylib
    }

    pub fn release_overflow_checks(&self) -> Option<bool> {
        self.get(&["profile", "release", "overflow-checks"])
            .and_then(|v| v.as_bool())
    }

    /// 1-based line of a `[section]` header, if present.
    pub fn line_of_section(&self, header: &str) -> Option<usize> {
        self.source
            .lines()
            .position(|l| l.trim() == header)
            .map(|i| i + 1)
    }
}

/// The manifests being linted plus any workspace roots loaded from disk.
#[derive(Default)]
pub struct ManifestSet {
    manifests: Vec<Manifest>,
    /// root manifest index -> contract crate indices
    roots: BTreeMap<usize, Vec<usize>>,
    /// Indices of manifests loaded from disk (not part of the input).
    loaded: Vec<usize>,
}

impl ManifestSet {
    pub fn parse(files: &[SourceFile], errors: &mut Vec<(PathBuf, String)>) -> Self {
        let mut set = ManifestSet::default();
        for f in files {
            match Manifest::parse(f.path.clone(), f.source.clone()) {
                Ok(m) => set.manifests.push(m),
                Err(e) => errors.push((f.path.clone(), e)),
            }
        }
        let n = set.manifests.len();
        for i in 0..n {
            if set.manifests[i].is_contract_crate() {
                let root = set.find_root(i);
                set.roots.entry(root).or_default().push(i);
            }
        }
        set
    }

    fn index_of(&self, path: &Path) -> Option<usize> {
        self.manifests.iter().position(|m| m.path == path)
    }

    /// Nearest ancestor manifest with `[workspace]`, or the crate itself.
    fn find_root(&mut self, crate_idx: usize) -> usize {
        if self.manifests[crate_idx].is_workspace_root() {
            return crate_idx;
        }
        let crate_path = self.manifests[crate_idx].path.clone();
        let mut dirs: Vec<PathBuf> = crate_path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .skip(1)
            .map(Path::to_path_buf)
            .collect();
        // Relative paths stop at the current directory; continue above it on disk.
        if crate_path.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                dirs.extend(cwd.ancestors().skip(1).map(Path::to_path_buf));
            }
        }
        for dir in dirs {
            let candidate = if dir.as_os_str().is_empty() {
                PathBuf::from("Cargo.toml")
            } else {
                dir.join("Cargo.toml")
            };
            let idx = match self.index_of(&candidate) {
                Some(i) => i,
                None => {
                    let Ok(src) = std::fs::read_to_string(&candidate) else {
                        continue;
                    };
                    let Ok(m) = Manifest::parse(candidate, src) else {
                        continue;
                    };
                    self.manifests.push(m);
                    self.loaded.push(self.manifests.len() - 1);
                    self.manifests.len() - 1
                }
            };
            if self.manifests[idx].is_workspace_root() {
                return idx;
            }
        }
        crate_idx
    }

    /// Each profile-owning root manifest with the contract crates it governs.
    pub fn roots(&self) -> impl Iterator<Item = (&Manifest, Vec<&Manifest>)> {
        self.roots.iter().map(|(r, crates)| {
            (
                &self.manifests[*r],
                crates.iter().map(|c| &self.manifests[*c]).collect(),
            )
        })
    }

    /// Manifests read from disk, so reports can show snippets and honour suppressions.
    pub fn extra_sources(&self) -> Vec<SourceFile> {
        self.loaded
            .iter()
            .map(|&i| SourceFile {
                path: self.manifests[i].path.clone(),
                source: self.manifests[i].source.clone(),
            })
            .collect()
    }
}
