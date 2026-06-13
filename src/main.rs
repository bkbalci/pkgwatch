use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::process::Command;

mod cli;
mod config;
mod output;
mod scanner;

use cli::{Cli, Commands};
use config::RuntimeConfig;
use scanner::{Finding, Report, Severity};

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("pkgwatch: {error:#}");
            3
        }
    };

    std::process::exit(code);
}

async fn run() -> Result<i32> {
    let cli = Cli::parse();
    let paths = config::AppPaths::discover()?;
    let file_config = config::load(&paths)?;
    let runtime = RuntimeConfig::resolve(&file_config, &cli);

    let command = match (cli.file.clone(), cli.command.clone()) {
        (Some(path), None) => Commands::File { path },
        (Some(_), Some(_)) => {
            return Err(anyhow!("use either -f/--file or a subcommand, not both"))
        }
        (None, Some(command)) => command,
        (None, None) => return Err(anyhow!("missing command; try `pkgwatch --help`")),
    };

    match command {
        Commands::Init => {
            let config = config::init(&paths)?;
            print_init_instructions(&paths, &config);
            Ok(0)
        }
        Commands::Scan { package } => {
            let report = scan_package(&package, &runtime, &paths).await?;
            finish_report(&report, &cli, &runtime)
        }
        Commands::File { path } => {
            let report = scan_file(path, &runtime, &paths).await?;
            finish_report(&report, &cli, &runtime)
        }
        Commands::Batch => {
            let report = run_batch(&paths).await?;
            finish_report(&report, &cli, &runtime)
        }
        Commands::UpdateCheck => run_update_check(&cli, &runtime, &paths).await,
        Commands::UpdateList => {
            let report = update_list(&runtime, &paths).await?;
            finish_report(&report, &cli, &runtime)
        }
        Commands::Paru { args } => run_paru_wrapper(args, &cli, &runtime, &paths).await,
    }
}

async fn scan_package_targets(
    packages: Vec<String>,
    cli: &Cli,
    runtime: &RuntimeConfig,
    paths: &config::AppPaths,
) -> Result<i32> {
    let (targets, dependency_errors) =
        scanner::aur::dependency_closure(&packages, runtime.max_aur_packages).await;
    let targets = if targets.is_empty() {
        packages
    } else {
        targets
    };

    for package in targets {
        let mut report = scan_package(&package, runtime, paths).await?;
        report.errors.extend(dependency_errors.clone());
        let exit_code = finish_report(&report, cli, runtime)?;
        if exit_code != 0 {
            return Ok(exit_code);
        }
    }

    Ok(0)
}

async fn scan_package(
    package: &str,
    runtime: &RuntimeConfig,
    paths: &config::AppPaths,
) -> Result<Report> {
    let threat_list = scanner::malware_list::load_or_builtin(paths).await;
    let mut findings = Vec::new();
    let mut errors = threat_list.warnings.clone();
    let mut documents = Vec::new();
    let mut package_version = None;

    if threat_list.contains_package(package) {
        findings.push(
            Finding::new(
                Severity::Critical,
                "known-malicious-package",
                "Package appears in the known malicious package list",
                format!("{package} is present in {}", threat_list.source),
            )
            .with_score(95),
        );
    }

    let metadata = if !runtime.use_aur_metadata {
        findings.push(Finding::new(
            Severity::Info,
            "aur-metadata-skipped",
            "AUR metadata lookup skipped",
            "AUR metadata is disabled by config or --no-network",
        ));
        None
    } else {
        match scanner::aur::fetch_package_metadata(package).await {
            Ok(metadata) => {
                findings.extend(scanner::aur::metadata_findings(&metadata, paths).await);
                Some(metadata)
            }
            Err(error) => {
                errors.push(format!("AUR metadata lookup failed: {error:#}"));
                None
            }
        }
    };

    if runtime.no_network {
        findings.push(Finding::new(
            Severity::Info,
            "pkgbuild-fetch-skipped",
            "Remote PKGBUILD fetch skipped",
            "--no-network was supplied",
        ));
    } else {
        match scanner::aur::fetch_snapshot_documents(package, paths).await {
            Ok(snapshot_documents) => {
                let scan = scanner::pkgbuild::scan_documents(&snapshot_documents);
                package_version = scan.package_version;
                findings.extend(scan.findings);
                documents = snapshot_documents;
            }
            Err(snapshot_error) => match scanner::aur::fetch_pkgbuild(package).await {
                Ok(pkgbuild) => {
                    documents.push(scanner::pkgbuild::SourceDocument {
                        name: "PKGBUILD".to_owned(),
                        content: pkgbuild,
                    });
                    let scan = scanner::pkgbuild::scan_documents(&documents);
                    package_version = scan.package_version;
                    findings.extend(scan.findings);
                    errors.push(format!(
                        "snapshot fetch failed, scanned PKGBUILD only: {snapshot_error:#}"
                    ));
                }
                Err(error) => errors.push(format!(
                    "snapshot and PKGBUILD fetch failed: {snapshot_error:#}; {error:#}"
                )),
            },
        }
    }

    maybe_add_ai_review(package, &documents, &mut findings, &mut errors, runtime).await;

    Ok(Report::new(
        Some(package.to_owned()),
        metadata
            .as_ref()
            .map(|metadata| metadata.version.clone())
            .or(package_version),
        "aur",
        findings,
        metadata,
        errors,
        threat_list.updated_at_string(),
    ))
}

async fn scan_file(
    path: PathBuf,
    runtime: &RuntimeConfig,
    paths: &config::AppPaths,
) -> Result<Report> {
    let documents = scanner::pkgbuild::read_source_documents(&path)
        .with_context(|| format!("failed to scan {}", path.display()))?;
    let scan = scanner::pkgbuild::scan_documents(&documents);
    let threat_list = scanner::malware_list::load_or_builtin(paths).await;
    let mut findings = scan.findings;
    let mut errors = threat_list.warnings.clone();

    if let Some(package) = scan.package_name.as_deref() {
        if threat_list.contains_package(package) {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "known-malicious-package",
                    "Package appears in the known malicious package list",
                    format!("{package} is present in {}", threat_list.source),
                )
                .with_score(95),
            );
        }
    }

    let metadata = if !runtime.use_aur_metadata {
        None
    } else if let Some(package) = scan.package_name.as_deref() {
        match scanner::aur::fetch_package_metadata(package).await {
            Ok(metadata) => {
                findings.extend(scanner::aur::metadata_findings(&metadata, paths).await);
                Some(metadata)
            }
            Err(error) => {
                errors.push(format!("AUR metadata lookup failed: {error:#}"));
                None
            }
        }
    } else {
        None
    };

    let package = scan.package_name.or_else(|| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned)
    });

    maybe_add_ai_review(
        package.as_deref().unwrap_or("(unknown)"),
        &documents,
        &mut findings,
        &mut errors,
        runtime,
    )
    .await;

    Ok(Report::new(
        package,
        scan.package_version,
        path.display().to_string(),
        findings,
        metadata,
        errors,
        threat_list.updated_at_string(),
    ))
}

async fn run_batch(paths: &config::AppPaths) -> Result<Report> {
    let threat_list = scanner::malware_list::load_or_builtin(paths).await;
    let mut findings = Vec::new();
    let mut errors = threat_list.warnings.clone();

    let installed = match scanner::ioc::installed_foreign_packages().await {
        Ok(packages) => packages,
        Err(error) => {
            errors.push(format!("pacman -Qmq failed: {error:#}"));
            Vec::new()
        }
    };

    for package in &installed {
        if threat_list.contains_package(package) {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "known-malicious-package",
                    "Installed foreign package appears in known malicious package list",
                    package.clone(),
                )
                .with_score(95),
            );
        }
    }

    if installed.is_empty() {
        findings.push(Finding::new(
            Severity::Info,
            "batch-empty",
            "No installed foreign packages were returned by pacman -Qmq",
            "Nothing was checked in the installed package set",
        ));
    }

    let cache_findings = scanner::ioc::scan_paru_cache_for(&installed).await;
    findings.extend(cache_findings);

    Ok(Report::new(
        Some("installed-foreign-packages".to_owned()),
        None,
        "pacman -Qmq",
        findings,
        None,
        errors,
        threat_list.updated_at_string(),
    ))
}

async fn run_update_check(
    cli: &Cli,
    runtime: &RuntimeConfig,
    paths: &config::AppPaths,
) -> Result<i32> {
    if runtime.no_network {
        let report = Report::new(
            Some("pending-aur-updates".to_owned()),
            None,
            "paru -Qua",
            vec![Finding::new(
                Severity::Info,
                "update-check-skipped",
                "Pending AUR update check skipped",
                "--no-network was supplied",
            )],
            None,
            Vec::new(),
            None,
        );
        return finish_report(&report, cli, runtime);
    }

    let packages = match scanner::aur::fetch_pending_updates(&runtime.real_paru_path).await {
        Ok(packages) => packages,
        Err(error) => {
            let report = Report::new(
                Some("pending-aur-updates".to_owned()),
                None,
                "paru -Qua",
                Vec::new(),
                None,
                vec![format!("pending update check failed: {error:#}")],
                None,
            );
            return finish_report(&report, cli, runtime);
        }
    };

    if packages.is_empty() {
        let report = Report::new(
            Some("pending-aur-updates".to_owned()),
            None,
            "paru -Qua",
            vec![Finding::new(
                Severity::Info,
                "update-check-empty",
                "No pending AUR updates found",
                "paru -Qua returned no packages",
            )],
            None,
            Vec::new(),
            None,
        );
        return finish_report(&report, cli, runtime);
    }

    scan_package_targets(packages, cli, runtime, paths).await
}

async fn update_list(runtime: &RuntimeConfig, paths: &config::AppPaths) -> Result<Report> {
    if runtime.no_network {
        return Ok(Report::new(
            Some("threat-list".to_owned()),
            None,
            "cache",
            vec![Finding::new(
                Severity::Info,
                "update-skipped",
                "Threat list update skipped",
                "--no-network was supplied",
            )],
            None,
            Vec::new(),
            None,
        ));
    }

    match scanner::malware_list::refresh(paths).await {
        Ok(list) => Ok(Report::new(
            Some("threat-list".to_owned()),
            None,
            list.source.clone(),
            vec![Finding::new(
                Severity::Info,
                "threat-list-updated",
                "Threat list cache refreshed",
                format!("{} package names cached", list.packages.len()),
            )],
            None,
            Vec::new(),
            list.updated_at_string(),
        )),
        Err(error) => Ok(Report::new(
            Some("threat-list".to_owned()),
            None,
            "cache",
            Vec::new(),
            None,
            vec![format!("threat list update failed: {error:#}")],
            None,
        )),
    }
}

async fn run_paru_wrapper(
    args: Vec<String>,
    cli: &Cli,
    runtime: &RuntimeConfig,
    paths: &config::AppPaths,
) -> Result<i32> {
    if args.is_empty() {
        return Err(anyhow!("missing paru arguments after `pkgwatch paru --`"));
    }

    if runtime.wrapper_enabled && !cli::requests_repo_only(&args) {
        let packages = cli::extract_package_args(&args);
        if !packages.is_empty() {
            let exit_code = scan_package_targets(packages, cli, runtime, paths).await?;
            if exit_code != 0 {
                return Ok(exit_code);
            }
        }

        if cli::requests_system_upgrade(&args) {
            let exit_code = run_update_check(cli, runtime, paths).await?;
            if exit_code != 0 {
                return Ok(exit_code);
            }
        }
    }

    let status = Command::new(&runtime.real_paru_path)
        .args(args)
        .status()
        .await
        .with_context(|| format!("failed to execute {}", runtime.real_paru_path))?;

    Ok(status.code().unwrap_or(1))
}

fn finish_report(report: &Report, cli: &Cli, runtime: &RuntimeConfig) -> Result<i32> {
    if cli.json {
        output::print_json(report)?;
    } else {
        output::print_human(report)?;
        if report.severity >= Severity::High {
            let path = output::write_report_draft(report)?;
            eprintln!("Report draft written to {}", path.display());
        }
    }

    if should_block(report, cli, runtime)? {
        return Ok(2);
    }

    if runtime.strict && report.severity >= Severity::High {
        return Ok(1);
    }

    Ok(0)
}

fn should_block(report: &Report, cli: &Cli, runtime: &RuntimeConfig) -> Result<bool> {
    if cli.json || report.severity < runtime.ask_on {
        return Ok(false);
    }

    if runtime.yes && report.severity < runtime.block_on {
        return Ok(false);
    }

    if !io::stdin().is_terminal() {
        return Ok(report.severity >= runtime.block_on);
    }

    if report.severity >= runtime.block_on {
        eprint!(
            "Critical risk findings detected. Type INSTALL to continue, or press Enter to abort: "
        );
    } else {
        eprint!("Continue despite {} risk findings? [y/N] ", report.severity);
    }
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if report.severity >= runtime.block_on {
        return Ok(answer.trim() != "INSTALL");
    }

    Ok(!matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

async fn maybe_add_ai_review(
    package: &str,
    documents: &[scanner::pkgbuild::SourceDocument],
    findings: &mut Vec<Finding>,
    errors: &mut Vec<String>,
    runtime: &RuntimeConfig,
) {
    if documents.is_empty() {
        return;
    }

    let severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info);

    if !runtime.ai.enabled {
        return;
    }

    if !scanner::ai::should_review(severity, &runtime.ai) {
        findings.push(Finding::new(
            Severity::Info,
            "ai-review-threshold-skipped",
            "AI review skipped by threshold",
            format!(
                "Current static severity is {severity}; configured AI threshold is {:?}",
                runtime.ai.threshold
            ),
        ));
        return;
    }

    match scanner::ai::review(Some(package), documents, &runtime.ai).await {
        Ok(finding) => findings.push(finding),
        Err(error) if runtime.ai.fail_closed => findings.push(
            Finding::new(
                Severity::Critical,
                "ai-review-failed-closed",
                "AI review failed in fail-closed mode",
                format!("{error:#}"),
            )
            .with_score(80),
        ),
        Err(error) => errors.push(format!("AI review skipped: {error:#}")),
    }
}

fn print_init_instructions(paths: &config::AppPaths, config: &config::AppConfig) {
    println!("pkgwatch config: {}", paths.config_file.display());
    println!("real paru: {}", config.wrapper.real_paru_path);
    println!();
    println!("Add this shell function to your shell rc file to guard normal paru usage:");
    println!();
    println!("paru() {{");
    println!("  pkgwatch paru -- \"$@\"");
    println!("}}");
    println!();
    println!(
        "AI review is {} by default.",
        if config.ai.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("Edit config.toml or pass --ai to enable it for a command.");
}
