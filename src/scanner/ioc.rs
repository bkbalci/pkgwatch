use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

use super::{pkgbuild, Finding, Severity};

pub async fn installed_foreign_packages() -> Result<Vec<String>> {
    let output = Command::new("pacman")
        .args(["-Qmq"])
        .output()
        .await
        .context("failed to execute pacman")?;

    if !output.status.success() {
        return Err(anyhow!("pacman exited with {}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub async fn scan_paru_cache_for(packages: &[String]) -> Vec<Finding> {
    let Some(cache_dir) = dirs::cache_dir() else {
        return Vec::new();
    };

    let paru_clone_dir = cache_dir.join("paru").join("clone");
    let mut findings = Vec::new();

    for package in packages {
        let pkgbuild = paru_clone_dir.join(package).join("PKGBUILD");
        if !pkgbuild.is_file() {
            continue;
        }

        match tokio::fs::read_to_string(&pkgbuild).await {
            Ok(content) => {
                findings.extend(pkgbuild_findings_for_cache(package, &pkgbuild, &content));
            }
            Err(error) => findings.push(Finding::new(
                Severity::Info,
                "paru-cache-read-failed",
                "Failed to read cached PKGBUILD",
                format!("{}: {error:#}", pkgbuild.display()),
            )),
        }
    }

    findings
}

fn pkgbuild_findings_for_cache(package: &str, path: &Path, content: &str) -> Vec<Finding> {
    pkgbuild::scan_content(&format!("paru-cache/{package}/PKGBUILD"), content)
        .into_iter()
        .map(|finding| {
            Finding::new(
                finding.severity,
                finding.rule_id,
                format!("Cached {package}: {}", finding.title),
                finding.description,
            )
            .with_evidence(
                finding
                    .evidence
                    .unwrap_or_else(|| path.display().to_string()),
            )
            .with_score(finding.score)
        })
        .collect()
}
