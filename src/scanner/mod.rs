use std::fmt;

use serde::{Deserialize, Serialize};

pub mod ai;
pub mod aur;
pub mod ioc;
pub mod malware_list;
pub mod pkgbuild;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub score: u8,
}

impl Finding {
    pub fn new(
        severity: Severity,
        rule_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let score = match severity {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 20,
            Severity::High => 45,
            Severity::Critical => 80,
        };

        Self {
            severity,
            rule_id: rule_id.into(),
            title: title.into(),
            description: description.into(),
            evidence: None,
            file: None,
            line: None,
            score,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_location(mut self, file: impl Into<String>, line: usize) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self
    }

    pub fn with_score(mut self, score: u8) -> Self {
        self.score = score;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub package: Option<String>,
    pub package_version: Option<String>,
    pub source: String,
    pub risk_score: u8,
    pub severity: Severity,
    pub findings: Vec<Finding>,
    pub metadata: Option<aur::AurPackage>,
    pub errors: Vec<String>,
    pub list_updated_at: Option<String>,
}

impl Report {
    pub fn new(
        package: Option<String>,
        package_version: Option<String>,
        source: impl Into<String>,
        findings: Vec<Finding>,
        metadata: Option<aur::AurPackage>,
        errors: Vec<String>,
        list_updated_at: Option<String>,
    ) -> Self {
        let severity = findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info);
        let mut risk_score = findings
            .iter()
            .map(|finding| finding.score as u16)
            .sum::<u16>()
            .min(100) as u8;

        if severity == Severity::Critical {
            risk_score = risk_score.max(90);
        }

        Self {
            package,
            package_version,
            source: source.into(),
            risk_score,
            severity,
            findings,
            metadata,
            errors,
            list_updated_at,
        }
    }
}
