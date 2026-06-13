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
