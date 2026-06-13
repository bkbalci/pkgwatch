use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::scanner::{Finding, Report, Severity};

pub fn print_json(report: &Report) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

pub fn print_human(report: &Report) -> Result<()> {
    let package = report.package.as_deref().unwrap_or("(unknown)");
    println!("{}", format!("pkgwatch report: {package}").bold());
    if let Some(version) = report.package_version.as_deref() {
        println!("version: {version}");
    }
    println!("source: {}", report.source);
    println!(
        "risk: {} ({})",
        color_score(report.risk_score),
        color_severity(report.severity)
    );

    if let Some(updated_at) = report.list_updated_at.as_deref() {
        println!("threat list: {updated_at}");
    }

    if let Some(metadata) = report.metadata.as_ref() {
        println!();
        println!("{}", "AUR metadata".bold());
        println!("version: {}", metadata.version);
        if let Some(maintainer) = metadata.maintainer.as_deref() {
            println!("maintainer: {maintainer}");
        }
        if let Some(votes) = metadata.num_votes {
            println!("votes: {votes}");
        }
        if let Some(popularity) = metadata.popularity {
            println!("popularity: {popularity:.4}");
        }
        if metadata.out_of_date.is_some() {
            println!("out-of-date: yes");
        }
    }

    println!();
    println!("{}", "Findings".bold());
    if report.findings.is_empty() {
        println!("  {}", "none".green());
    } else {
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let group = report
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect::<Vec<_>>();
            if group.is_empty() {
                continue;
            }

            println!("  {}", color_severity(severity).bold());
            for finding in group {
                print_finding(finding);
            }
        }
    }

    if !report.errors.is_empty() {
        println!();
        println!("{}", "Errors / skipped checks".bold());
        for error in &report.errors {
            println!("  - {error}");
        }
    }

    Ok(())
}

pub fn write_report_draft(report: &Report) -> Result<PathBuf> {
    let package = report.package.as_deref().unwrap_or("unknown");
    let path = std::env::temp_dir().join(format!("pkgwatch-report-{}.txt", sanitize(package)));
    fs::write(&path, report_draft(report))?;
    Ok(path)
}

fn report_draft(report: &Report) -> String {
    let mut draft = String::new();
    draft.push_str("pkgwatch report draft\n");
    draft.push_str("=====================\n\n");
    draft.push_str(&format!(
        "Package: {}\n",
        report.package.as_deref().unwrap_or("(unknown)")
    ));
    if let Some(version) = report.package_version.as_deref() {
        draft.push_str(&format!("Version: {version}\n"));
    }
    draft.push_str(&format!("Source: {}\n", report.source));
    draft.push_str(&format!("Risk score: {}\n", report.risk_score));
    draft.push_str(&format!("Severity: {}\n", report.severity));
    if let Some(updated_at) = report.list_updated_at.as_deref() {
        draft.push_str(&format!("Threat list updated at: {updated_at}\n"));
    }

    if let Some(metadata) = report.metadata.as_ref() {
        draft.push_str("\nAUR metadata\n");
        draft.push_str(&format!("Name: {}\n", metadata.name));
        draft.push_str(&format!("Version: {}\n", metadata.version));
        if let Some(maintainer) = metadata.maintainer.as_deref() {
            draft.push_str(&format!("Maintainer: {maintainer}\n"));
        }
        if let Some(votes) = metadata.num_votes {
            draft.push_str(&format!("Votes: {votes}\n"));
        }
        if let Some(popularity) = metadata.popularity {
            draft.push_str(&format!("Popularity: {popularity:.4}\n"));
        }
    }

    draft.push_str("\nFindings\n");
    if report.findings.is_empty() {
        draft.push_str("- none\n");
    } else {
        for finding in &report.findings {
            let location = match (&finding.file, finding.line) {
                (Some(file), Some(line)) => format!(" ({file}:{line})"),
                (Some(file), None) => format!(" ({file})"),
                _ => String::new(),
            };
            draft.push_str(&format!(
                "- [{}] {}{}\n  rule: {}\n  {}\n",
                finding.severity, finding.title, location, finding.rule_id, finding.description
            ));
            if let Some(evidence) = finding.evidence.as_deref() {
                draft.push_str(&format!("  evidence: {evidence}\n"));
            }
        }
    }

    if !report.errors.is_empty() {
        draft.push_str("\nErrors / skipped checks\n");
        for error in &report.errors {
            draft.push_str(&format!("- {error}\n"));
        }
    }

    draft
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn print_finding(finding: &Finding) {
    let location = match (&finding.file, finding.line) {
        (Some(file), Some(line)) => format!(" ({file}:{line})"),
        (Some(file), None) => format!(" ({file})"),
        _ => String::new(),
    };

    println!("    - {}{}", finding.title, location);
    println!("      rule: {}", finding.rule_id);
    println!("      {}", finding.description);
    if let Some(evidence) = finding.evidence.as_deref() {
        println!("      evidence: {evidence}");
    }
}

fn color_score(score: u8) -> colored::ColoredString {
    let text = score.to_string();
    match score {
        0..=19 => text.green(),
        20..=49 => text.yellow(),
        50..=79 => text.red(),
        _ => text.red().bold(),
    }
}

fn color_severity(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Info => "info".normal(),
        Severity::Low => "low".green(),
        Severity::Medium => "medium".yellow(),
        Severity::High => "high".red(),
        Severity::Critical => "critical".red().bold(),
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::{Finding, Report, Severity};

    use super::write_report_draft;

    #[test]
    fn writes_report_draft_for_findings() {
        let report = Report::new(
            Some("bad/pkg".to_owned()),
            Some("1.0".to_owned()),
            "fixture",
            vec![Finding::new(
                Severity::Critical,
                "test-rule",
                "Suspicious behavior",
                "example",
            )],
            None,
            Vec::new(),
            None,
        );

        let path = write_report_draft(&report).unwrap();
        let content = std::fs::read_to_string(path).unwrap();

        assert!(content.contains("Package: bad/pkg"));
        assert!(content.contains("test-rule"));
    }
}
