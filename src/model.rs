//! Types partagés : statut d'un certificat, résultat d'une vérification.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Statut d'une cible, du plus sain au plus grave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Certificat valide, échéance lointaine.
    Ok,
    /// Échéance sous le seuil d'avertissement.
    Warning,
    /// Échéance sous le seuil critique.
    Critical,
    /// Chaîne non approuvée, nom ne correspondant pas, signature faible…
    Invalid,
    /// Certificat expiré (ou pas encore valide).
    Expired,
    /// Impossible de joindre l'hôte ou d'établir la session TLS.
    Error,
}

impl Status {
    pub const ALL: [Status; 6] = [
        Status::Ok,
        Status::Warning,
        Status::Critical,
        Status::Invalid,
        Status::Expired,
        Status::Error,
    ];

    /// Code de sortie façon Nagios : 0 = OK, 1 = avertissement, 2 = critique.
    pub fn exit_code(self) -> i32 {
        match self {
            Status::Ok => 0,
            Status::Warning => 1,
            _ => 2,
        }
    }

    pub fn label_fr(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Warning => "À renouveler",
            Status::Critical => "Critique",
            Status::Invalid => "Invalide",
            Status::Expired => "Expiré",
            Status::Error => "Injoignable",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warning => "warning",
            Status::Critical => "critical",
            Status::Invalid => "invalid",
            Status::Expired => "expired",
            Status::Error => "error",
        }
    }

    /// Un statut demande-t-il une action humaine ?
    pub fn is_problem(self) -> bool {
        self != Status::Ok
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Status::ALL
            .into_iter()
            .find(|st| st.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                format!("statut inconnu « {s} » (attendu : ok, warning, critical, invalid, expired, error)")
            })
    }
}

/// Un certificat de la chaîne présentée par le serveur.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// Horodatage Unix (secondes).
    pub not_before: i64,
    /// Horodatage Unix (secondes).
    pub not_after: i64,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub key: String,
    pub signature_algorithm: String,
    pub is_ca: bool,
}

/// Résultat complet de la vérification d'une cible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Nom envoyé en SNI et vérifié (l'hôte, sauf `sni` différent).
    pub server_name: String,
    pub status: Status,
    /// Jours restants avant l'expiration effective (le maillon de la chaîne qui expire en premier).
    pub days_remaining: Option<i64>,
    /// Horodatage Unix de l'expiration effective.
    pub expires_at: Option<i64>,
    /// Résumé lisible du problème principal, ou de l'état.
    pub message: String,
    /// Tous les points relevés (chaîne, clé faible, SHA-1, intermédiaire qui expire avant le certificat…).
    pub issues: Vec<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    /// Certificat final puis intermédiaires, dans l'ordre envoyé par le serveur.
    pub chain: Vec<CertInfo>,
    pub tags: Vec<String>,
    /// Horodatage Unix de la vérification.
    pub checked_at: i64,
    pub duration_ms: u64,
}

impl CheckResult {
    pub fn key(&self) -> String {
        target_key(&self.host, self.port)
    }

    pub fn leaf(&self) -> Option<&CertInfo> {
        self.chain.first()
    }
}

/// Clé unique d'une cible, avec crochets pour l'IPv6.
pub fn target_key(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Seuils appliqués à une cible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub warning_days: i64,
    pub critical_days: i64,
}

/// Calcule le statut à partir des faits relevés.
///
/// Règles, de la plus grave à la moins grave :
/// 1. pas de chaîne lue → `Error` ;
/// 2. un maillon expiré ou pas encore valide → `Expired` ;
/// 3. échec de validation (CA inconnue, nom, révocation…) → `Invalid` ;
/// 4. jours restants ≤ seuil critique → `Critical` ;
/// 5. jours restants ≤ seuil d'avertissement → `Warning` ;
/// 6. sinon `Ok`.
///
/// Les faiblesses (clé courte, SHA-1) font au minimum passer en `Warning`.
pub fn classify(
    days_remaining: Option<i64>,
    not_yet_valid: bool,
    validation_error: Option<&str>,
    has_weakness: bool,
    t: Thresholds,
) -> Status {
    let Some(days) = days_remaining else {
        return Status::Error;
    };
    if days < 0 || not_yet_valid {
        return Status::Expired;
    }
    if validation_error.is_some() {
        return Status::Invalid;
    }
    if days <= t.critical_days {
        return Status::Critical;
    }
    if days <= t.warning_days || has_weakness {
        return Status::Warning;
    }
    Status::Ok
}

/// Jours entiers restants entre `now` et `not_after` (arrondi vers le bas, négatif si expiré).
pub fn days_between(now: i64, not_after: i64) -> i64 {
    (not_after - now).div_euclid(86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Thresholds = Thresholds {
        warning_days: 30,
        critical_days: 14,
    };

    #[test]
    fn classement_par_seuils() {
        assert_eq!(classify(Some(90), false, None, false, T), Status::Ok);
        assert_eq!(classify(Some(31), false, None, false, T), Status::Ok);
        assert_eq!(classify(Some(30), false, None, false, T), Status::Warning);
        assert_eq!(classify(Some(15), false, None, false, T), Status::Warning);
        assert_eq!(classify(Some(14), false, None, false, T), Status::Critical);
        assert_eq!(classify(Some(0), false, None, false, T), Status::Critical);
        assert_eq!(classify(Some(-1), false, None, false, T), Status::Expired);
    }

    #[test]
    fn expiration_prime_sur_invalide() {
        assert_eq!(
            classify(Some(-3), false, Some("CA inconnue"), false, T),
            Status::Expired
        );
        assert_eq!(classify(Some(200), true, None, false, T), Status::Expired);
    }

    #[test]
    fn invalide_prime_sur_les_seuils() {
        assert_eq!(
            classify(Some(5), false, Some("nom"), false, T),
            Status::Invalid
        );
    }

    #[test]
    fn faiblesse_donne_au_moins_un_avertissement() {
        assert_eq!(classify(Some(300), false, None, true, T), Status::Warning);
        assert_eq!(classify(Some(3), false, None, true, T), Status::Critical);
    }

    #[test]
    fn sans_chaine_c_est_une_erreur() {
        assert_eq!(classify(None, false, None, false, T), Status::Error);
    }

    #[test]
    fn calcul_des_jours() {
        let now = 1_700_000_000;
        assert_eq!(days_between(now, now + 86_400 * 10 + 5), 10);
        assert_eq!(days_between(now, now + 86_399), 0);
        assert_eq!(days_between(now, now - 1), -1);
    }

    #[test]
    fn ordre_et_codes_de_sortie() {
        assert!(Status::Error > Status::Expired && Status::Warning > Status::Ok);
        assert_eq!(Status::Ok.exit_code(), 0);
        assert_eq!(Status::Warning.exit_code(), 1);
        assert_eq!(Status::Invalid.exit_code(), 2);
        assert_eq!("CRITICAL".parse::<Status>().unwrap(), Status::Critical);
        assert!("bof".parse::<Status>().is_err());
    }

    #[test]
    fn cle_ipv6() {
        assert_eq!(target_key("::1", 443), "[::1]:443");
        assert_eq!(target_key("exemple.fr", 8443), "exemple.fr:8443");
    }
}
