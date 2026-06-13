use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "pkgwatch",
    version,
    about = "Review AUR PKGBUILD content before install"
)]
pub struct Cli {
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub json: bool,

    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub strict: bool,

    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub no_network: bool,

    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub yes: bool,

    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub ai: bool,

    #[arg(long, global = true, value_enum)]
    pub ai_provider: Option<AiProviderArg>,

    #[arg(long, global = true, value_enum)]
    pub ai_threshold: Option<SeverityArg>,

    #[arg(long, global = true, value_name = "PATH")]
    pub ai_custom_command: Option<String>,

    #[arg(short = 'f', long = "file", global = true, value_name = "PATH")]
    pub file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Create the default config and print shell wrapper instructions.
    Init,
    /// Fetch and scan an AUR package by name.
    Scan { package: String },
    /// Scan a local PKGBUILD file or package directory.
    File { path: PathBuf },
    /// Check installed foreign packages and local paru cache.
    Batch,
    /// Scan pending AUR updates without installing anything.
    UpdateCheck,
    /// Refresh the cached known-malicious package list.
    UpdateList,
    /// Scan package arguments, then delegate to paru.
    Paru {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AiProviderArg {
    Auto,
    Codex,
    Claude,
    Gemini,
    Custom,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Always,
}

pub fn extract_package_args(args: &[String]) -> Vec<String> {
    let mut packages = Vec::new();
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            continue;
        }

        if arg.starts_with("--") {
            if matches!(
                arg.as_str(),
                "--color" | "--config" | "--dbpath" | "--root" | "--cachedir" | "--gpgdir"
            ) {
                skip_next = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        packages.push(arg.to_owned());
    }

    packages
}

pub fn requests_system_upgrade(args: &[String]) -> bool {
    let mut saw_sync = false;
    let mut saw_upgrade = false;

    for arg in args {
        if arg == "--sysupgrade" {
            saw_upgrade = true;
            continue;
        }

        if let Some(shorts) = arg.strip_prefix('-') {
            if shorts.starts_with('-') {
                continue;
            }

            if shorts.contains('S') {
                saw_sync = true;
            }
            if shorts.contains('u') {
                saw_upgrade = true;
            }
        }
    }

    saw_sync && saw_upgrade
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{extract_package_args, requests_system_upgrade, Cli, Commands};

    #[test]
    fn extracts_non_flag_paru_arguments() {
        let args = vec![
            "-S".to_owned(),
            "--needed".to_owned(),
            "example-bin".to_owned(),
            "other".to_owned(),
        ];

        assert_eq!(extract_package_args(&args), vec!["example-bin", "other"]);
    }

    #[test]
    fn detects_system_upgrade_flags_only_from_options() {
        assert!(requests_system_upgrade(&["-Syu".to_owned()]));
        assert!(!requests_system_upgrade(&[
            "-S".to_owned(),
            "ungoogled-bin".to_owned()
        ]));
    }

    #[test]
    fn parses_paru_trailing_args_after_separator() {
        let cli = Cli::parse_from(["pkgwatch", "paru", "--", "-Syu"]);

        match cli.command {
            Some(Commands::Paru { args }) => assert_eq!(args, vec!["-Syu"]),
            other => panic!("expected paru command, got {other:?}"),
        }
    }
}
