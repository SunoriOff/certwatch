//! Lecture et validation du fichier de configuration TOML.

use crate::model::{Status, Thresholds, target_key};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, rename = "alert")]
    pub alerts: Vec<AlertConfig>,
    #[serde(default, rename = "target")]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub warning_days: i64,
    pub critical_days: i64,
    pub timeout_secs: u64,
    pub concurrency: usize,
    /// Intervalle entre deux scans en mode `serve`.
    pub interval_minutes: u64,
    pub listen: String,
    /// Mémoire des statuts, pour n'alerter qu'aux changements.
    pub state_file: PathBuf,
    /// CA supplémentaires à approuver (PKI interne), au format PEM.
    pub ca_files: Vec<PathBuf>,
    /// N'approuver que `ca_files`, sans les CA publiques.
    pub only_custom_ca: bool,
    /// Fichier texte d'une cible par ligne (`hôte`, `hôte:port`, `# commentaire`).
    pub targets_file: Option<PathBuf>,
    /// Proxy HTTP (méthode CONNECT), ex. `http://utilisateur:motdepasse@proxy:3128`.
    pub proxy: Option<String>,
    /// Lire `HTTPS_PROXY` / `NO_PROXY` si `proxy` est vide.
    pub use_env_proxy: bool,
    /// Suffixes ou hôtes contactés sans proxy.
    pub no_proxy: Vec<String>,
    /// Jeton exigé pour `POST /api/scan` (vide = scan manuel désactivé).
    pub api_token: Option<String>,
    /// Relancer une alerte toutes les N heures tant que le problème persiste (0 = jamais).
    pub reminder_hours: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            warning_days: 30,
            critical_days: 14,
            timeout_secs: 10,
            concurrency: 16,
            interval_minutes: 360,
            listen: "127.0.0.1:8088".into(),
            state_file: PathBuf::from("certwatch-state.json"),
            ca_files: Vec::new(),
            only_custom_ca: false,
            targets_file: None,
            proxy: None,
            use_env_proxy: false,
            no_proxy: Vec::new(),
            api_token: None,
            reminder_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertKind {
    /// JSON brut, pour un outil maison, n8n, GLPI…
    Webhook,
    Slack,
    /// Microsoft Teams (flux « Workflows », carte adaptative).
    Teams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertConfig {
    pub kind: AlertKind,
    pub url: String,
    /// Statut minimal qui déclenche une alerte (retour à la normale toujours signalé).
    #[serde(default = "default_min_status")]
    pub min_status: Status,
    /// Ne concerne que les cibles portant au moins une de ces étiquettes (vide = toutes).
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_min_status() -> Status {
    Status::Warning
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Nom affiché ; l'hôte par défaut.
    pub name: Option<String>,
    /// Nom envoyé en SNI et vérifié dans le certificat ; l'hôte par défaut.
    pub sni: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub warning_days: Option<i64>,
    pub critical_days: Option<i64>,
    /// Négocier TLS après une phase en clair (messagerie) : `smtp`, `imap` ou `pop3`.
    pub starttls: Option<StartTls>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StartTls {
    Smtp,
    Imap,
    Pop3,
}

fn default_port() -> u16 {
    443
}

impl Target {
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.host.clone())
    }

    pub fn server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }

    pub fn key(&self) -> String {
        target_key(&self.host, self.port)
    }

    pub fn thresholds(&self, s: &Settings) -> Thresholds {
        Thresholds {
            warning_days: self.warning_days.unwrap_or(s.warning_days),
            critical_days: self.critical_days.unwrap_or(s.critical_days),
        }
    }

    /// Lit `hôte`, `hôte:port`, `[ipv6]:port` ou une URL `https://hôte:port/chemin`.
    pub fn parse(spec: &str) -> Result<Target> {
        let mut s = spec.trim();
        if let Some(rest) = s.strip_prefix("https://") {
            s = rest;
        }
        if let Some(idx) = s.find('/') {
            s = &s[..idx];
        }
        if s.is_empty() {
            bail!("cible vide");
        }
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let end = rest
                .find(']')
                .with_context(|| format!("IPv6 sans crochet fermant : {spec}"))?;
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => p
                    .parse()
                    .with_context(|| format!("port invalide : {spec}"))?,
                None if after.is_empty() => 443,
                None => bail!("cible invalide : {spec}"),
            };
            (host.to_string(), port)
        } else if s.matches(':').count() > 1 {
            // IPv6 sans crochets ni port
            (s.to_string(), 443)
        } else if let Some((h, p)) = s.rsplit_once(':') {
            (
                h.to_string(),
                p.parse()
                    .with_context(|| format!("port invalide : {spec}"))?,
            )
        } else {
            (s.to_string(), 443)
        };
        if host.is_empty() {
            bail!("hôte vide : {spec}");
        }
        if port == 0 {
            bail!("le port 0 n'est pas valable : {spec}");
        }
        Ok(Target {
            host: host.to_ascii_lowercase(),
            port,
            name: None,
            sni: None,
            tags: Vec::new(),
            warning_days: None,
            critical_days: None,
            starttls: None,
        })
    }
}

impl Config {
    /// Charge le fichier, ajoute les cibles de `targets_file`, puis valide.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("lecture de {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("format de {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.resolve_paths(base);
        if let Some(file) = cfg.settings.targets_file.clone() {
            let list = std::fs::read_to_string(&file)
                .with_context(|| format!("lecture de {}", file.display()))?;
            cfg.targets.extend(parse_target_list(&list)?);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Les chemins relatifs sont relatifs au fichier de configuration, pas au dossier courant.
    fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.settings.state_file);
        for p in &mut self.settings.ca_files {
            fix(p);
        }
        if let Some(p) = &mut self.settings.targets_file {
            fix(p);
        }
    }

    pub fn validate(&self) -> Result<()> {
        let s = &self.settings;
        if s.timeout_secs == 0 || s.timeout_secs > 300 {
            bail!("timeout_secs doit être compris entre 1 et 300");
        }
        if s.concurrency == 0 || s.concurrency > 512 {
            bail!("concurrency doit être compris entre 1 et 512");
        }
        if s.interval_minutes == 0 {
            bail!("interval_minutes doit être supérieur à 0");
        }
        if s.only_custom_ca && s.ca_files.is_empty() {
            bail!("only_custom_ca = true exige au moins un fichier dans ca_files");
        }
        let mut seen = HashSet::new();
        for t in &self.targets {
            let th = t.thresholds(s);
            if th.critical_days < 0 || th.warning_days < th.critical_days {
                bail!(
                    "{} : il faut 0 ≤ critical_days ({}) ≤ warning_days ({})",
                    t.key(),
                    th.critical_days,
                    th.warning_days
                );
            }
            if t.host.trim().is_empty() {
                bail!("une cible n'a pas d'hôte");
            }
            if !seen.insert(t.key()) {
                bail!("cible en double : {}", t.key());
            }
        }
        if s.warning_days < s.critical_days || s.critical_days < 0 {
            bail!("il faut 0 ≤ critical_days ≤ warning_days dans [settings]");
        }
        for a in &self.alerts {
            if !(a.url.starts_with("https://") || a.url.starts_with("http://")) {
                bail!("l'URL d'alerte doit commencer par https:// ou http://");
            }
        }
        if let Some(p) = &s.proxy {
            crate::probe::ProxyConfig::parse(p)?;
        }
        Ok(())
    }
}

/// Une cible par ligne ; lignes vides et `#` ignorées ; étiquettes facultatives après un espace.
pub fn parse_target_list(text: &str) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let spec = parts.next().unwrap_or_default();
        let mut t = Target::parse(spec).with_context(|| format!("ligne {}", i + 1))?;
        t.tags = parts.map(str::to_string).collect();
        out.push(t);
    }
    Ok(out)
}

pub const EXAMPLE_CONFIG: &str = include_str!("../examples/certwatch.toml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse_des_cibles() {
        let t = Target::parse("Intranet.Exemple.fr").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("intranet.exemple.fr", 443));
        let t = Target::parse("mail.exemple.fr:8443").unwrap();
        assert_eq!(t.port, 8443);
        let t = Target::parse("https://portail.exemple.fr:9443/connexion").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("portail.exemple.fr", 9443));
        let t = Target::parse("[2001:db8::1]:636").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 636));
        let t = Target::parse("2001:db8::2").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::2", 443));
        assert!(Target::parse("hote:abc").is_err());
        assert!(Target::parse("hote:0").is_err());
        assert!(Target::parse("  ").is_err());
    }

    #[test]
    fn liste_de_cibles_avec_commentaires_et_etiquettes() {
        let list =
            "# serveurs web\nwww.exemple.fr prod web\n\nldap.exemple.fr:636 annuaire # LDAPS\n";
        let v = parse_target_list(list).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].tags, vec!["prod", "web"]);
        assert_eq!(v[1].port, 636);
        assert_eq!(v[1].tags, vec!["annuaire"]);
    }

    #[test]
    fn exemple_fourni_valide() {
        let cfg: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.targets.is_empty());
    }

    #[test]
    fn refuse_les_doublons_et_les_seuils_incoherents() {
        let cfg: Config =
            toml::from_str("[[target]]\nhost='a.fr'\n[[target]]\nhost='a.fr'\nport=443\n").unwrap();
        assert!(cfg.validate().unwrap_err().to_string().contains("double"));

        let cfg: Config =
            toml::from_str("[[target]]\nhost='a.fr'\nwarning_days=5\ncritical_days=10\n").unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config = toml::from_str("[settings]\nonly_custom_ca=true\n").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn champ_inconnu_refuse() {
        assert!(toml::from_str::<Config>("[settings]\nwarnig_days=3\n").is_err());
    }

    #[test]
    fn seuils_par_cible() {
        let s = Settings::default();
        let mut t = Target::parse("a.fr").unwrap();
        assert_eq!(t.thresholds(&s).warning_days, 30);
        t.warning_days = Some(60);
        assert_eq!(t.thresholds(&s).warning_days, 60);
        assert_eq!(t.thresholds(&s).critical_days, 14);
    }
}
