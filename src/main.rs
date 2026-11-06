use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tenantfence::{config::Config, report::Report, spec::Spec};

#[derive(Parser)]
#[command(
    version,
    about = "Test tenant boundaries before your users do.",
    after_help = "Examples:\n  tenantfence init --output tenantfence.yaml\n  tenantfence inspect --config examples/cloudflare-d1/tenantfence.yaml\n  tenantfence run --config tenantfence.yaml --authorized --output reports\n  tenantfence report --input reports/report.json --output report.html"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Write a commented configuration; never generates credentials.
    Init {
        #[arg(long, default_value = "tenantfence.yaml")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Validate mappings and preview bounded coverage without HTTP or credentials.
    Inspect {
        #[arg(long, default_value = "tenantfence.yaml")]
        config: PathBuf,
    },
    /// Run tests against an explicitly authorized API and disposable fixtures.
    Run {
        #[arg(long, default_value = "tenantfence.yaml")]
        config: PathBuf,
        #[arg(long, required = true)]
        authorized: bool,
        #[arg(long, default_value = "reports")]
        output: PathBuf,
    },
    /// Render a versioned JSON report without API access.
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
async fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Init { output, force } => {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true);
            if force {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            let template = include_str!("../examples/cloudflare-d1/tenantfence.yaml")
                .replace("writes: true", "writes: false")
                .replace(
                    "required: [read, collection, mutation, export]",
                    "required: [read, collection, export]",
                );
            options
                .open(output)
                .context("create configuration (use --force to replace)")?
                .write_all(template.as_bytes())?;
            println!(
                "Configuration written. Set target.spec relative to this file and supply the named token environment variables before running."
            );
            Ok(0)
        }
        Command::Inspect { config } => {
            let c = Config::load(&config)?;
            let spec = Spec::load(&c.target.spec)?;
            spec.validate(&c)?;
            print!("{}", spec.inspect(&c));
            Ok(0)
        }
        Command::Run {
            config,
            authorized,
            output,
        } => {
            ensure!(authorized, "run requires --authorized");
            let c = Config::load(&config)?;
            let spec = Spec::load(&c.target.spec)?;
            spec.validate(&c)?;
            let credentials = c.credentials()?;
            let report = tenantfence::engine::run(c, spec, credentials).await?;
            report.write(&output)?;
            println!("{}\nReports: {}", report.summary(), output.display());
            Ok(report.exit_code())
        }
        Command::Report { input, output } => {
            ensure!(
                std::fs::metadata(&input)?.len() <= 32 * 1024 * 1024,
                "report input exceeds 32 MiB"
            );
            let r: Report = serde_json::from_slice(&std::fs::read(input)?)
                .context("parse TenantFence JSON report")?;
            r.validate()?;
            std::fs::write(output, r.html())?;
            Ok(0)
        }
    }
}
#[tokio::main]
async fn main() {
    let code = match execute(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("TenantFence: {e:#}");
            2
        }
    };
    std::process::exit(code);
}
