use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::config::AppPaths;

use super::{pkgbuild::SourceDocument, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all(deserialize = "PascalCase"))]
pub struct AurPackage {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub url: Option<String>,
    #[serde(rename(deserialize = "PackageBase"))]
    pub package_base: Option<String>,
    #[serde(rename(deserialize = "PackageBaseID"))]
    pub package_base_id: Option<u64>,
    #[serde(rename(deserialize = "NumVotes"))]
    pub num_votes: Option<u64>,
    pub popularity: Option<f64>,
    #[serde(rename(deserialize = "OutOfDate"))]
    pub out_of_date: Option<i64>,
    pub maintainer: Option<String>,
    pub first_submitted: Option<i64>,
    pub last_modified: Option<i64>,
    pub depends: Option<Vec<String>>,
    pub make_depends: Option<Vec<String>>,
    pub check_depends: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    resultcount: u64,
    results: Vec<AurPackage>,
}

pub async fn fetch_package_metadata(package: &str) -> Result<AurPackage> {
    let url = format!("https://aur.archlinux.org/rpc/v5/info/{package}");
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<RpcResponse>()
        .await?;

    response
        .results
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("AUR RPC returned no result for {package}"))
}

pub async fn fetch_pending_updates(paru_path: &str) -> Result<Vec<String>> {
    let output = Command::new(paru_path)
        .arg("-Qua")
        .output()
        .await
        .with_context(|| format!("failed to execute {paru_path} -Qua"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "paru -Qua failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(parse_update_packages(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn parse_update_packages(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect()
}

pub async fn dependency_closure(
    root_packages: &[String],
    max_packages: usize,
) -> (Vec<String>, Vec<String>) {
    let mut ordered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::from(root_packages.to_vec());
    let roots = root_packages
        .iter()
        .map(|package| normalize_dep_name(package))
        .collect::<std::collections::HashSet<_>>();
    let mut errors = Vec::new();

    while let Some(package) = queue.pop_front() {
        let normalized = normalize_dep_name(&package);
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }

        if ordered.len() >= max_packages {
            errors.push(format!(
                "AUR dependency scan capped at {max_packages} package(s); remaining dependencies skipped"
            ));
            break;
        }

        match fetch_package_metadata(&normalized).await {
            Ok(metadata) => {
                ordered.push(normalized);
                for dependency in metadata.dependency_names() {
                    if !seen.contains(&dependency) {
                        queue.push_back(dependency);
                    }
                }
            }
            Err(error) => {
                if roots.contains(&normalized) || !is_missing_aur_package_error(&error) {
                    errors.push(format!(
                        "{normalized}: dependency metadata lookup skipped: {error:#}"
                    ));
                }
            }
        }
    }

    (ordered, errors)
}

fn is_missing_aur_package_error(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("AUR RPC returned no result")
}

impl AurPackage {
    pub fn dependency_names(&self) -> Vec<String> {
        self.depends
            .iter()
            .chain(self.make_depends.iter())
            .chain(self.check_depends.iter())
            .flat_map(|dependencies| dependencies.iter())
            .map(|dependency| normalize_dep_name(dependency))
            .filter(|dependency| !dependency.is_empty())
            .collect()
    }
}

pub fn normalize_dep_name(dependency: &str) -> String {
    dependency
        .split(['<', '>', '=', ':'])
        .next()
        .unwrap_or("")
        .trim()
        .to_owned()
}

pub async fn fetch_pkgbuild(package: &str) -> Result<String> {
    let url = format!("https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={package}");
    let response = reqwest::Client::new().get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "PKGBUILD fetch returned HTTP {}",
            response.status()
        ));
    }

    response.text().await.map_err(Into::into)
}

pub async fn fetch_snapshot_documents(
    package: &str,
    paths: &AppPaths,
) -> Result<Vec<SourceDocument>> {
    let snapshot_dir = paths.cache_dir.join("snapshots");
    tokio::fs::create_dir_all(&snapshot_dir)
        .await
        .with_context(|| format!("failed to create {}", snapshot_dir.display()))?;

    let archive_path = snapshot_dir.join(format!("{package}.tar.gz"));
    let url = format!("https://aur.archlinux.org/cgit/aur.git/snapshot/{package}.tar.gz");
    let bytes = reqwest::Client::new()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    tokio::fs::write(&archive_path, &bytes)
        .await
        .with_context(|| format!("failed to write {}", archive_path.display()))?;

    read_snapshot_documents(package, &archive_path).await
}

async fn read_snapshot_documents(
    package: &str,
    archive_path: &Path,
) -> Result<Vec<SourceDocument>> {
    let entries = list_archive_entries(archive_path).await?;
    validate_archive_entries(&entries)?;

    let source_entries = entries
        .into_iter()
        .filter(|entry| is_scannable_snapshot_entry(entry))
        .collect::<Vec<_>>();

    if source_entries.is_empty() {
        return Err(anyhow!(
            "snapshot archive contains no scannable package files"
        ));
    }

    let mut documents = Vec::new();
    for entry in source_entries {
        let content = extract_archive_entry(archive_path, &entry).await?;
        let name = entry
            .strip_prefix(&format!("{package}/"))
            .unwrap_or(&entry)
            .to_owned();
        documents.push(SourceDocument { name, content });
    }

    Ok(documents)
}

pub fn is_scannable_snapshot_entry(entry: &str) -> bool {
    if entry.ends_with('/') {
        return false;
    }

    let Some(name) = Path::new(entry).file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    matches!(name, "PKGBUILD" | ".SRCINFO")
        || name.ends_with(".install")
        || name.ends_with(".sh")
        || name.starts_with("prepare")
        || name.starts_with("build")
        || name.starts_with("install")
}

async fn list_archive_entries(archive_path: &Path) -> Result<Vec<String>> {
    let output = Command::new("tar")
        .arg("-tzf")
        .arg(archive_path)
        .output()
        .await
        .context("failed to execute tar for snapshot listing")?;

    if !output.status.success() {
        return Err(anyhow!(
            "tar listing failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

async fn extract_archive_entry(archive_path: &Path, entry: &str) -> Result<String> {
    let output = Command::new("tar")
        .arg("-xOzf")
        .arg(archive_path)
        .arg(entry)
        .output()
        .await
        .with_context(|| format!("failed to execute tar for {entry}"))?;

    if !output.status.success() {
        return Err(anyhow!(
            "tar extraction failed for {entry}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn validate_archive_entries(entries: &[String]) -> Result<()> {
    for entry in entries {
        let path = PathBuf::from(entry);
        if path.is_absolute() || entry.split('/').any(|part| part == "..") {
            return Err(anyhow!("snapshot archive contains unsafe path: {entry}"));
        }
    }

    Ok(())
}

pub async fn metadata_findings(metadata: &AurPackage, paths: &AppPaths) -> Vec<Finding> {
    let mut findings = Vec::new();

    if metadata.out_of_date.is_some() {
        findings.push(Finding::new(
            Severity::Low,
            "aur-out-of-date",
            "AUR package is flagged out of date",
            "The package may have stale build instructions",
        ));
    }

    if is_recent(metadata.first_submitted, 30) {
        findings.push(Finding::new(
            Severity::Medium,
            "aur-new-package",
            "AUR package was submitted recently",
            "New packages have less community review history",
        ));
    }

    if is_recent(metadata.last_modified, 14)
        && metadata.num_votes.unwrap_or_default() <= 5
        && metadata.popularity.unwrap_or_default() < 0.1
    {
        findings.push(Finding::new(
            Severity::Medium,
            "aur-low-review-recent-change",
            "Low-review package changed recently",
            "Low votes/popularity plus recent changes deserve manual review",
        ));
    }

    if let Some(maintainer) = metadata.maintainer.as_deref() {
        match fetch_maintainer_package_count(maintainer).await {
            Ok(count) if count <= 1 => findings.push(Finding::new(
                Severity::Medium,
                "aur-low-maintainer-history",
                "Maintainer has very few AUR packages",
                format!("{maintainer} currently maintains {count} package(s) in AUR RPC search"),
            )),
            Ok(_) => {}
            Err(error) => findings.push(Finding::new(
                Severity::Info,
                "aur-maintainer-history-skipped",
                "Maintainer package count lookup failed",
                format!("{error:#}"),
            )),
        }

        if let Some(previous) = maintainer_snapshot_change(paths, &metadata.name, maintainer) {
            findings.push(Finding::new(
                Severity::Low,
                "aur-maintainer-changed",
                "Maintainer changed since previous local scan",
                format!("previous: {previous}, current: {maintainer}"),
            ));
        }
    }

    findings
}

async fn fetch_maintainer_package_count(maintainer: &str) -> Result<u64> {
    let url = format!("https://aur.archlinux.org/rpc/v5/search/{maintainer}");
    let response = reqwest::Client::new()
        .get(url)
        .query(&[("by", "maintainer")])
        .send()
        .await?
        .error_for_status()?
        .json::<RpcResponse>()
        .await?;

    Ok(response.resultcount)
}

fn is_recent(timestamp: Option<i64>, days: i64) -> bool {
    let Some(timestamp) = timestamp else {
        return false;
    };
    let Some(datetime) = Utc.timestamp_opt(timestamp, 0).single() else {
        return false;
    };

    Utc::now().signed_duration_since(datetime).num_days() <= days
}

fn maintainer_snapshot_change(paths: &AppPaths, package: &str, maintainer: &str) -> Option<String> {
    let mut snapshot = read_snapshot(paths).unwrap_or_default();
    let previous = snapshot.insert(package.to_owned(), maintainer.to_owned());

    if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
        let _ = fs::write(&paths.maintainer_snapshot, json);
    }

    previous.filter(|previous| previous != maintainer)
}

fn read_snapshot(paths: &AppPaths) -> Result<HashMap<String, String>> {
    let raw = fs::read_to_string(&paths.maintainer_snapshot)
        .with_context(|| format!("failed to read {}", paths.maintainer_snapshot.display()))?;

    serde_json::from_str(&raw).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        is_scannable_snapshot_entry, normalize_dep_name, parse_update_packages,
        validate_archive_entries, AurPackage, RpcResponse,
    };

    #[test]
    fn parses_aur_rpc_response() {
        let raw = r#"{
  "version": 5,
  "type": "multiinfo",
  "resultcount": 1,
  "results": [{
    "Name": "example-bin",
    "Version": "1.2.3-1",
    "Description": "Example",
    "PackageBase": "example-bin",
    "PackageBaseID": 42,
    "NumVotes": 3,
    "Popularity": 0.01,
    "OutOfDate": null,
    "Maintainer": "tester",
    "FirstSubmitted": 1700000000,
    "LastModified": 1700000100
  }]
}"#;

        let response: RpcResponse = serde_json::from_str(raw).unwrap();
        let package: &AurPackage = &response.results[0];

        assert_eq!(response.resultcount, 1);
        assert_eq!(package.name, "example-bin");
        assert_eq!(package.package_base_id, Some(42));
        assert_eq!(package.num_votes, Some(3));
    }

    #[test]
    fn rejects_unsafe_snapshot_paths() {
        let entries = vec!["pkg/PKGBUILD".to_owned(), "pkg/../evil".to_owned()];

        assert!(validate_archive_entries(&entries).is_err());
    }

    #[test]
    fn parses_pending_update_package_names() {
        let packages = parse_update_packages("foo 1-1 -> 1-2\nbar-bin 2 -> 3\n");

        assert_eq!(packages, vec!["foo", "bar-bin"]);
    }

    #[test]
    fn normalizes_dependency_constraints() {
        assert_eq!(normalize_dep_name("libfoo>=1.2"), "libfoo");
        assert_eq!(normalize_dep_name("python: optional note"), "python");
    }

    #[test]
    fn selects_snapshot_helper_files() {
        assert!(is_scannable_snapshot_entry("pkg/PKGBUILD"));
        assert!(is_scannable_snapshot_entry("pkg/.SRCINFO"));
        assert!(is_scannable_snapshot_entry("pkg/hook.install"));
        assert!(is_scannable_snapshot_entry("pkg/scripts/build.sh"));
        assert!(!is_scannable_snapshot_entry("pkg/image.png"));
    }
}
