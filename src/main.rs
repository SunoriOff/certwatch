use anyhow::{Context, Result, bail};
use certwatch::config::{Config, Target};
use certwatch::model::{CheckResult, Status};
use certwatch::probe::{Prober, now_unix};
use certwatch::{alert, report, scan, server};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// Surveille les certificats TLS : expirations, chaînes invalides, alertes et tableau de bord.
#[derive(Parser)]
#[command(name = "certwatch", version, about, long_about = None)]
struct Cli {
    /// Fichier de configuration TOML.
    #[arg(short, long, global = true, default_value = "certwatch.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Vérifie toutes les cibles une fois et affiche le résultat (code de sortie 0, 1 ou 2).
    Check {
        /// Cibles ponctuelles (hôte, hôte:port, URL) ; sans configuration si le fichier est absent.
        #[arg(long = "host", value_name = "CIBLE")]
        hosts: Vec<String>,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// N'afficher que les cibles qui demandent une action.
        #[arg(long)]
        only_problems: bool,
        /// Envoyer les alertes configurées (usage depuis cron ou une tâche planifiée).
        #[arg(long)]
        alert: bool,
        /// Désactiver les couleurs.
        #[arg(long)]
        no_color: bool,
    },
    /// Détaille la chaîne de certificats d'une cible.
    Inspect {
        /// hôte, hôte:port ou URL
        target: String,
        /// Nom SNI différent de l'hôte.
        #[arg(long)]
        sni: Option<String>,
        #[arg(long, value_enum)]
        starttls: Option<StartTlsArg>,
        #[arg(long)]
        json: bool,
    },
    /// Lance le service : scans périodiques, tableau de bord, API et métriques.
    Serve,
    /// Affiche un exemple de configuration commenté.
    Init,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
enum StartTlsArg {
    Smtp,
    Imap,
    Pop3,
}

fn load_config(path: &Path, required: bool) -> Result<Config> {
    if path.exists() {
        Config::load(path)
    } else if required {
        bail!(
            "configuration introuvable : {} (créez-la avec « certwatch init > {} »)",
            path.display(),
            path.display()
        )
    } else {
        Ok(Config::default())
    }
}

#[tokio::main]
async fn main() {
    certwatch::install_crypto();
    let cli = Cli::parse();
    let default_level = if matches!(cli.command, Command::Serve) {
        "info"
    } else {
        "warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .with_writer(std::io::stderr)
        .init();

    match run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("erreur : {e:#}");
            std::process::exit(3);
        }
    }
}

async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Init => {
            print!("{}", certwatch::config::EXAMPLE_CONFIG);
            Ok(0)
        }
        Command::Check {
            hosts,
            format,
            only_problems,
            alert,
            no_color,
        } => {
            let mut cfg = load_config(&cli.config, hosts.is_empty())?;
            if !hosts.is_empty() {
                cfg.targets = hosts
                    .iter()
                    .map(|h| Target::parse(h))
                    .collect::<Result<_>>()?;
                cfg.validate()?;
            }
            if cfg.targets.is_empty() {
                bail!("aucune cible à vérifier");
            }
            let prober = Prober::new(&cfg.settings)?;
            let results = scan::scan(&cfg, &prober, &cfg.targets).await;
            let worst = results.iter().map(|r| r.status).max().unwrap_or(Status::Ok);

            if alert {
                if cfg.alerts.is_empty() {
                    bail!("--alert demandé mais aucune section [[alert]] dans la configuration");
                }
                let mut state = alert::State::load(&cfg.settings.state_file)?;
                let events = alert::plan(
                    &mut state,
                    &results,
                    &cfg.alerts,
                    cfg.settings.reminder_hours,
                    now_unix(),
                );
                let sent = alert::send_all(&cfg.alerts, &events).await;
                state.save(&cfg.settings.state_file)?;
                eprintln!("{sent}/{} alerte(s) envoyée(s)", events.len());
            }

            let shown: Vec<CheckResult> = results
                .into_iter()
                .filter(|r| !only_problems || r.status.is_problem())
                .collect();
            match format {
                Format::Table => {
                    let color = !no_color
                        && std::io::stdout().is_terminal()
                        && std::env::var_os("NO_COLOR").is_none();
                    if shown.is_empty() {
                        println!("Aucun problème : tous les certificats sont en règle.");
                    } else {
                        print!("{}", report::table(&shown, color));
                    }
                }
                Format::Json => println!("{}", serde_json::to_string_pretty(&shown)?),
                Format::Csv => print!("{}", report::csv(&shown)),
            }
            Ok(worst.exit_code())
        }
        Command::Inspect {
            target,
            sni,
            starttls,
            json,
        } => {
            let cfg = load_config(&cli.config, false)?;
            let mut t = Target::parse(&target)?;
            t.sni = sni;
            t.starttls = starttls.map(|s| match s {
                StartTlsArg::Smtp => certwatch::config::StartTls::Smtp,
                StartTlsArg::Imap => certwatch::config::StartTls::Imap,
                StartTlsArg::Pop3 => certwatch::config::StartTls::Pop3,
            });
            let prober = Prober::new(&cfg.settings)?;
            let r = prober.check(&t, t.thresholds(&cfg.settings)).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print_inspect(&r);
            }
            Ok(r.status.exit_code())
        }
        Command::Serve => {
            let cfg = load_config(&cli.config, true)?;
            if cfg.targets.is_empty() {
                bail!("aucune cible dans la configuration");
            }
            let listen = cfg.settings.listen.clone();
            let st = server::AppState::new(cfg)?;
            tokio::spawn(server::scheduler(st.clone()));
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("écoute sur {listen}"))?;
            tracing::info!("tableau de bord : http://{listen}/");
            axum::serve(listener, server::router(st))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            Ok(0)
        }
    }
}

fn print_inspect(r: &CheckResult) {
    println!("{} — {}", r.key(), r.status.label_fr());
    println!("  {}", r.message);
    if let (Some(v), Some(c)) = (&r.tls_version, &r.cipher_suite) {
        println!("  Protocole : {v} · {c}");
    }
    println!("  Durée : {} ms", r.duration_ms);
    for i in &r.issues {
        println!("  ! {i}");
    }
    for (n, c) in r.chain.iter().enumerate() {
        let role = if n == 0 {
            "Certificat du site"
        } else if c.subject == c.issuer {
            "Racine (auto-signée)"
        } else {
            "Intermédiaire"
        };
        println!("\n  [{}] {role}", n + 1);
        println!("      Sujet      : {}", c.subject);
        println!("      Émetteur   : {}", c.issuer);
        println!(
            "      Validité   : du {} au {}",
            alert::format_date(c.not_before),
            alert::format_date(c.not_after)
        );
        println!(
            "      Clé        : {} · signature {}",
            c.key, c.signature_algorithm
        );
        println!("      Série      : {}", c.serial);
        if !c.dns_names.is_empty() {
            println!("      Noms (SAN) : {}", c.dns_names.join(", "));
        }
        if !c.ip_addresses.is_empty() {
            println!("      IP (SAN)   : {}", c.ip_addresses.join(", "));
        }
    }
}
