use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{AiProviderArg, Cli, SeverityArg};
use crate::scanner::Severity;

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub cache_dir: PathBuf,
    pub config_file: PathBuf,
    pub threat_cache: PathBuf,
    pub maintainer_snapshot: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("pkgwatch");
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("pkgwatch");

        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("failed to create {}", cache_dir.display()))?;
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("failed to create {}", config_dir.display()))?;

        Ok(Self {
            cache_dir: cache_dir.clone(),
            config_file: config_dir.join("config.toml"),
            threat_cache: cache_dir.join("threat-list.json"),
            maintainer_snapshot: cache_dir.join("maintainers.json"),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub policy: PolicyConfig,
    pub network: NetworkConfig,
    pub ai: AiConfig,
    pub wrapper: WrapperConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub strict: bool,
    pub ask_on: Severity,
    pub block_on: Severity,
    pub yes: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            strict: false,
            ask_on: Severity::High,
            block_on: Severity::Critical,
            yes: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub auto_update_list: bool,
    pub use_aur_metadata: bool,
    pub max_aur_packages: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            auto_update_list: true,
            use_aur_metadata: true,
            max_aur_packages: 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub provider: AiProvider,
    pub threshold: AiThreshold,
    pub timeout_seconds: u64,
    pub fail_closed: bool,
    pub custom_command: Option<String>,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AiProvider::Auto,
            threshold: AiThreshold::Medium,
            timeout_seconds: 45,
            fail_closed: false,
            custom_command: None,
            max_file_bytes: 64 * 1024,
            max_total_bytes: 240 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WrapperConfig {
    pub enabled: bool,
    pub real_paru_path: String,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            real_paru_path: find_in_path("paru").unwrap_or_else(|| "/usr/bin/paru".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    #[default]
    Auto,
    Codex,
    Claude,
    Gemini,
    Custom,
}

impl From<AiProviderArg> for AiProvider {
    fn from(value: AiProviderArg) -> Self {
        match value {
            AiProviderArg::Auto => Self::Auto,
            AiProviderArg::Codex => Self::Codex,
            AiProviderArg::Claude => Self::Claude,
            AiProviderArg::Gemini => Self::Gemini,
            AiProviderArg::Custom => Self::Custom,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AiThreshold {
    Always,
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl AiThreshold {
    pub fn allows(self, severity: Severity) -> bool {
        match self {
            Self::Always => true,
            Self::Info => severity >= Severity::Info,
            Self::Low => severity >= Severity::Low,
            Self::Medium => severity >= Severity::Medium,
            Self::High => severity >= Severity::High,
            Self::Critical => severity >= Severity::Critical,
        }
    }
}

impl From<SeverityArg> for AiThreshold {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Always => Self::Always,
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub strict: bool,
    pub no_network: bool,
    pub yes: bool,
    pub ask_on: Severity,
    pub block_on: Severity,
    pub use_aur_metadata: bool,
    pub max_aur_packages: usize,
    pub ai: AiConfig,
    pub wrapper_enabled: bool,
    pub real_paru_path: String,
}

impl RuntimeConfig {
    pub fn resolve(file_config: &AppConfig, cli: &Cli) -> Self {
        let mut ai = file_config.ai.clone();
        if cli.ai {
            ai.enabled = true;
        }
        if let Some(provider) = cli.ai_provider {
            ai.provider = provider.into();
        }
        if let Some(threshold) = cli.ai_threshold {
            ai.threshold = threshold.into();
        }
        if let Some(custom_command) = cli.ai_custom_command.as_ref() {
            ai.custom_command = Some(custom_command.clone());
            ai.provider = AiProvider::Custom;
        }

        Self {
            strict: file_config.policy.strict || cli.strict,
            no_network: cli.no_network,
            yes: file_config.policy.yes || cli.yes,
            ask_on: file_config.policy.ask_on,
            block_on: file_config.policy.block_on,
            use_aur_metadata: file_config.network.use_aur_metadata && !cli.no_network,
            max_aur_packages: file_config.network.max_aur_packages.max(1),
            ai,
            wrapper_enabled: file_config.wrapper.enabled,
            real_paru_path: file_config.wrapper.real_paru_path.clone(),
        }
    }
}

pub fn load(paths: &AppPaths) -> Result<AppConfig> {
    if !paths.config_file.exists() {
        return Ok(AppConfig::default());
    }

    let raw = fs::read_to_string(&paths.config_file)
        .with_context(|| format!("failed to read {}", paths.config_file.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", paths.config_file.display()))
}

pub fn init(paths: &AppPaths) -> Result<AppConfig> {
    let config = if paths.config_file.exists() {
        load(paths)?
    } else {
        let config = AppConfig::default();
        let toml = toml::to_string_pretty(&config)?;
        fs::write(&paths.config_file, toml)
            .with_context(|| format!("failed to write {}", paths.config_file.display()))?;
        config
    };

    Ok(config)
}

pub fn find_in_path(binary: &str) -> Option<String> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::cli::Cli;
    use clap::Parser;

    use super::{AiProvider, AiThreshold, AppConfig, RuntimeConfig};

    #[test]
    fn cli_ai_flags_override_config() {
        let config = AppConfig::default();
        let cli = Cli::parse_from([
            "pkgwatch",
            "--ai",
            "--ai-provider",
            "gemini",
            "--ai-threshold",
            "high",
            "file",
            "PKGBUILD",
        ]);

        let runtime = RuntimeConfig::resolve(&config, &cli);

        assert!(runtime.ai.enabled);
        assert_eq!(runtime.ai.provider, AiProvider::Gemini);
        assert_eq!(runtime.ai.threshold, AiThreshold::High);
    }

    #[test]
    fn cli_custom_ai_command_selects_custom_provider() {
        let config = AppConfig::default();
        let cli = Cli::parse_from([
            "pkgwatch",
            "--ai-custom-command",
            "/tmp/local-review",
            "file",
            "PKGBUILD",
        ]);

        let runtime = RuntimeConfig::resolve(&config, &cli);

        assert_eq!(runtime.ai.provider, AiProvider::Custom);
        assert_eq!(
            runtime.ai.custom_command,
            Some("/tmp/local-review".to_owned())
        );
    }
}
