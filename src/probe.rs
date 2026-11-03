//! Connexion TLS à une cible et analyse de la chaîne de certificats.
//!
//! Le vérificateur maison laisse la poignée de main aller jusqu'au bout même si la chaîne
//! est invalide : on veut lire le certificat d'un site *mal configuré*, pas seulement
//! constater qu'il l'est. Le verdict du vérificateur standard (webpki) est conservé à part.

use crate::config::{Settings, StartTls, Target};
use crate::model::{CertInfo, CheckResult, Status, Thresholds, classify, days_between};
use anyhow::{Context, Result, bail};
use base64::Engine;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// Proxy HTTP utilisé en tunnel (méthode CONNECT).
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    /// En-tête `Proxy-Authorization` déjà encodé.
    pub auth: Option<String>,
}

impl ProxyConfig {
    pub fn parse(url: &str) -> Result<ProxyConfig> {
        let rest = url
            .trim()
            .strip_prefix("http://")
            .context("le proxy doit être de la forme http://hôte:port")?;
        let rest = rest.trim_end_matches('/');
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((cred, hp)) => (
                Some(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(cred)
                )),
                hp,
            ),
            None => (None, rest),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().context("port du proxy invalide")?),
            None => (hostport, 3128),
        };
        if host.is_empty() {
            bail!("hôte du proxy vide");
        }
        Ok(ProxyConfig {
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            auth,
        })
    }
}

/// `no_proxy` : `*`, hôte exact, ou suffixe (`.exemple.local` ou `exemple.local`).
pub fn bypass_proxy(host: &str, rules: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    rules.iter().any(|r| {
        let r = r.trim().to_ascii_lowercase();
        if r.is_empty() {
            return false;
        }
        if r == "*" || r == host {
            return true;
        }
        let suffix = r.trim_start_matches('*').trim_start_matches('.');
        host.ends_with(&format!(".{suffix}")) || host == suffix
    })
}

/// Ce que le vérificateur a vu pendant la poignée de main.
#[derive(Debug, Default)]
struct Capture {
    chain: Vec<CertificateDer<'static>>,
    verdict: Option<Result<(), rustls::Error>>,
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    capture: Arc<Mutex<Capture>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ());
        let mut cap = self.capture.lock().expect("verrou de capture");
        cap.chain = std::iter::once(end_entity.clone().into_owned())
            .chain(intermediates.iter().map(|c| c.clone().into_owned()))
            .collect();
        cap.verdict = Some(verdict);
        // On accepte toujours : le verdict réel est rendu dans le rapport.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Outil de vérification partagé entre toutes les cibles d'un scan.
#[derive(Clone)]
pub struct Prober {
    provider: Arc<CryptoProvider>,
    verifier: Arc<WebPkiServerVerifier>,
    timeout: Duration,
    proxy: Option<ProxyConfig>,
    no_proxy: Vec<String>,
}

impl Prober {
    pub fn new(settings: &Settings) -> Result<Prober> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        if !settings.only_custom_ca {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for path in &settings.ca_files {
            let pem = std::fs::read(path)
                .with_context(|| format!("lecture de la CA {}", path.display()))?;
            let mut added = 0;
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert.with_context(|| format!("PEM illisible : {}", path.display()))?;
                roots
                    .add(cert)
                    .with_context(|| format!("CA refusée : {}", path.display()))?;
                added += 1;
            }
            if added == 0 {
                bail!("aucun certificat trouvé dans {}", path.display());
            }
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .context("construction du vérificateur")?;

        let (proxy, no_proxy) = match &settings.proxy {
            Some(p) => (Some(ProxyConfig::parse(p)?), settings.no_proxy.clone()),
            None if settings.use_env_proxy => {
                let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
                let p = env("HTTPS_PROXY").or_else(|| env("https_proxy"));
                let mut np = settings.no_proxy.clone();
                if let Some(v) = env("NO_PROXY").or_else(|| env("no_proxy")) {
                    np.extend(v.split(',').map(|s| s.trim().to_string()));
                }
                (p.map(|p| ProxyConfig::parse(&p)).transpose()?, np)
            }
            None => (None, Vec::new()),
        };

        Ok(Prober {
            provider,
            verifier,
            timeout: Duration::from_secs(settings.timeout_secs),
            proxy,
            no_proxy,
        })
    }

    /// Vérifie une cible. Ne renvoie jamais d'erreur : tout échec devient un statut `Error`.
    pub async fn check(&self, target: &Target, th: Thresholds) -> CheckResult {
        let started = Instant::now();
        let now = now_unix();
        let mut result = CheckResult {
            name: target.display_name(),
            host: target.host.clone(),
            port: target.port,
            server_name: target.server_name().to_string(),
            status: Status::Error,
            days_remaining: None,
            expires_at: None,
            message: String::new(),
            issues: Vec::new(),
            tls_version: None,
            cipher_suite: None,
            chain: Vec::new(),
            tags: target.tags.clone(),
            checked_at: now,
            duration_ms: 0,
        };

        match tokio::time::timeout(self.timeout, self.handshake(target)).await {
            Err(_) => {
                result.message = format!("Délai dépassé ({} s)", self.timeout.as_secs());
            }
            Ok(Err(e)) => {
                result.message = describe_error(&e);
            }
            Ok(Ok(hs)) => analyse(&mut result, hs, now, th),
        }
        result.duration_ms = started.elapsed().as_millis() as u64;
        result
    }

    async fn handshake(&self, target: &Target) -> Result<Handshake> {
        let mut tcp = self.connect(&target.host, target.port).await?;
        if let Some(proto) = target.starttls {
            starttls(&mut tcp, proto).await?;
        }

        let capture = Arc::new(Mutex::new(Capture::default()));
        let verifier = Arc::new(RecordingVerifier {
            inner: self.verifier.clone(),
            capture: capture.clone(),
        });
        let config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("versions TLS")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let name = ServerName::try_from(target.server_name().to_string())
            .with_context(|| format!("nom de serveur invalide : {}", target.server_name()))?;

        let connector = TlsConnector::from(Arc::new(config));
        let tls = connector.connect(name, tcp).await.map_err(|e| {
            anyhow::Error::new(e).context("négociation TLS impossible (TLS 1.2 minimum requis)")
        })?;
        let conn = tls.get_ref().1;
        let tls_version = conn.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
            other => format!("{other:?}"),
        });
        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()));
        drop(tls);

        let cap = std::mem::take(&mut *capture.lock().expect("verrou de capture"));
        if cap.chain.is_empty() {
            bail!("le serveur n'a présenté aucun certificat");
        }
        Ok(Handshake {
            chain: cap.chain,
            verdict: cap.verdict.unwrap_or(Ok(())),
            tls_version,
            cipher_suite,
        })
    }

    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        match &self.proxy {
            Some(p) if !bypass_proxy(host, &self.no_proxy) => {
                connect_via_proxy(p, host, port).await
            }
            _ => TcpStream::connect((host, port))
                .await
                .map_err(anyhow::Error::from),
        }
    }
}

struct Handshake {
    chain: Vec<CertificateDer<'static>>,
    verdict: Result<(), rustls::Error>,
    tls_version: Option<String>,
    cipher_suite: Option<String>,
}

fn analyse(r: &mut CheckResult, hs: Handshake, now: i64, th: Thresholds) {
    r.tls_version = hs.tls_version;
    r.cipher_suite = hs.cipher_suite;

    let mut weak = false;
    for (i, der) in hs.chain.iter().enumerate() {
        match parse_cert(der) {
            Ok(info) => r.chain.push(info),
            Err(e) => r
                .issues
                .push(format!("Certificat n°{} illisible : {e}", i + 1)),
        }
    }
    let Some(leaf) = r.chain.first().cloned() else {
        r.message = "Certificat illisible".into();
        return;
    };

    // Le maillon qui expire en premier, hors racine auto-signée éventuellement envoyée.
    let effective = r
        .chain
        .iter()
        .filter(|c| c.subject != c.issuer || std::ptr::eq(*c, &r.chain[0]))
        .min_by_key(|c| c.not_after)
        .cloned()
        .unwrap_or_else(|| leaf.clone());
    if effective.not_after < leaf.not_after {
        r.issues.push(format!(
            "Un certificat intermédiaire ({}) expire avant le certificat du site",
            effective.subject
        ));
    }
    let not_yet_valid = leaf.not_before > now;
    if not_yet_valid {
        r.issues
            .push("Le certificat n'est pas encore valide".into());
    }

    for (i, c) in r.chain.iter().enumerate() {
        let role = if i == 0 { "du site" } else { "intermédiaire" };
        if let Some(bits) = rsa_bits(&c.key)
            && bits < 2048
        {
            r.issues.push(format!(
                "Clé RSA de {bits} bits trop courte (certificat {role})"
            ));
            weak = true;
        }
        if c.signature_algorithm.contains("SHA-1") && c.subject != c.issuer {
            r.issues
                .push(format!("Signature SHA-1 obsolète (certificat {role})"));
            weak = true;
        }
    }

    let validation_error = match &hs.verdict {
        Ok(()) => None,
        Err(e) => {
            let txt = describe_tls_error(e);
            // L'expiration est déjà traitée par les dates : pas de doublon.
            if !matches!(
                e,
                rustls::Error::InvalidCertificate(
                    CertificateError::Expired
                        | CertificateError::ExpiredContext { .. }
                        | CertificateError::NotValidYet
                        | CertificateError::NotValidYetContext { .. }
                )
            ) {
                r.issues.insert(0, txt.clone());
            }
            Some(txt)
        }
    };

    let days = days_between(now, effective.not_after);
    r.days_remaining = Some(days);
    r.expires_at = Some(effective.not_after);
    r.status = classify(
        Some(days),
        not_yet_valid,
        validation_error.as_deref(),
        weak,
        th,
    );
    r.message = match r.status {
        Status::Expired if not_yet_valid => "Certificat pas encore valide".into(),
        Status::Expired => format!("Expiré depuis {} jour(s)", -days),
        Status::Invalid => validation_error.unwrap_or_default(),
        Status::Critical | Status::Warning | Status::Ok => {
            let mut m = format!("Expire dans {days} jour(s)");
            if weak && r.status == Status::Warning && days > th.warning_days {
                m = format!("{m} — configuration faible");
            }
            m
        }
        Status::Error => "Erreur".into(),
    };
}

fn rsa_bits(key: &str) -> Option<usize> {
    key.strip_prefix("RSA ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Extrait les informations utiles d'un certificat DER.
pub fn parse_cert(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(d) => dns_names.push(d.to_string()),
                GeneralName::IPAddress(bytes) => ip_addresses.push(format_ip(bytes)),
                _ => {}
            }
        }
    }
    let key = match cert.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => format!("RSA {} bits", rsa.key_size()),
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => format!("ECDSA {} bits", ec.key_size()),
        _ => match cert
            .public_key()
            .algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            other => format!("autre ({other})"),
        },
    };
    Ok(CertInfo {
        subject: short_name(cert.subject()),
        issuer: short_name(cert.issuer()),
        serial: cert.raw_serial_as_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        dns_names,
        ip_addresses,
        key,
        signature_algorithm: signature_name(&cert.signature_algorithm.algorithm.to_id_string()),
        is_ca: cert.is_ca(),
    })
}

/// CN si présent, sinon O, sinon le nom complet.
fn short_name(name: &X509Name<'_>) -> String {
    let first = |it: &mut dyn Iterator<Item = &AttributeTypeAndValue<'_>>| {
        it.next().and_then(|a| a.as_str().ok()).map(str::to_string)
    };
    first(&mut name.iter_common_name())
        .or_else(|| first(&mut name.iter_organization()))
        .unwrap_or_else(|| name.to_string())
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "RSA SHA-1",
        "1.2.840.113549.1.1.11" => "RSA SHA-256",
        "1.2.840.113549.1.1.12" => "RSA SHA-384",
        "1.2.840.113549.1.1.13" => "RSA SHA-512",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.4.1" => "ECDSA SHA-1",
        "1.2.840.10045.4.3.2" => "ECDSA SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA SHA-512",
        "1.3.101.112" => "Ed25519",
        other => return other.to_string(),
    }
    .to_string()
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => format!("{bytes:02x?}"),
    }
}

/// Message lisible pour une erreur de validation rustls.
pub fn describe_tls_error(e: &rustls::Error) -> String {
    match e {
        rustls::Error::InvalidCertificate(ce) => match ce {
            CertificateError::UnknownIssuer => {
                "Autorité inconnue : chaîne incomplète ou CA non approuvée".into()
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "Le certificat ne couvre pas ce nom d'hôte".into()
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "Certificat expiré".into()
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "Certificat pas encore valide".into()
            }
            CertificateError::Revoked => "Certificat révoqué".into(),
            CertificateError::BadSignature => "Signature de la chaîne invalide".into(),
            CertificateError::UnsupportedSignatureAlgorithmContext { .. } => {
                "Algorithme de signature non pris en charge".into()
            }
            CertificateError::BadEncoding => "Certificat mal encodé".into(),
            other => format!("Certificat refusé ({other:?})"),
        },
        other => format!("Erreur TLS : {other}"),
    }
}

fn describe_error(e: &anyhow::Error) -> String {
    let full = format!("{e:#}");
    let lower = full.to_lowercase();
    if lower.contains("lookup address")
        || lower.contains("name or service not known")
        || lower.contains("no address associated")
        || lower.contains("nodename nor servname")
    {
        "Nom introuvable (DNS)".into()
    } else if lower.contains("connection refused") {
        "Connexion refusée (port fermé ?)".into()
    } else if lower.contains("network is unreachable") || lower.contains("no route to host") {
        "Hôte injoignable (réseau)".into()
    } else if lower.contains("connection reset") {
        "Connexion réinitialisée par le serveur".into()
    } else {
        full
    }
}

async fn connect_via_proxy(p: &ProxyConfig, host: &str, port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect((p.host.as_str(), p.port))
        .await
        .with_context(|| format!("proxy {}:{} injoignable", p.host, p.port))?;
    let authority = crate::model::target_key(host, port);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(a) = &p.auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // Lecture octet par octet jusqu'à la fin des en-têtes : rien ne doit être consommé au-delà.
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            bail!("le proxy a fermé la connexion");
        }
        head.push(b[0]);
        if head.len() > 16 * 1024 {
            bail!("réponse du proxy trop longue");
        }
    }
    let status_line = String::from_utf8_lossy(&head);
    let status_line = status_line.lines().next().unwrap_or_default();
    let code = status_line.split_whitespace().nth(1).unwrap_or_default();
    if code != "200" {
        bail!("le proxy refuse le tunnel : {status_line}");
    }
    Ok(s)
}

async fn read_line(s: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b).await? == 0 {
            bail!("connexion fermée pendant STARTTLS");
        }
        line.push(b[0]);
        if line.ends_with(b"\r\n") || line.len() > 4096 {
            return Ok(String::from_utf8_lossy(&line).trim_end().to_string());
        }
    }
}

/// Lit une réponse SMTP éventuellement multiligne (`250-…` puis `250 …`).
async fn read_smtp(s: &mut TcpStream) -> Result<String> {
    loop {
        let l = read_line(s).await?;
        if l.len() < 4 || l.as_bytes()[3] != b'-' {
            return Ok(l);
        }
    }
}

async fn starttls(s: &mut TcpStream, proto: StartTls) -> Result<()> {
    match proto {
        StartTls::Smtp => {
            let greet = read_smtp(s).await?;
            if !greet.starts_with("220") {
                bail!("bannière SMTP inattendue : {greet}");
            }
            s.write_all(b"EHLO certwatch\r\n").await?;
            let ehlo = read_smtp(s).await?;
            if !ehlo.starts_with("250") {
                bail!("EHLO refusé : {ehlo}");
            }
            s.write_all(b"STARTTLS\r\n").await?;
            let r = read_smtp(s).await?;
            if !r.starts_with("220") {
                bail!("STARTTLS refusé : {r}");
            }
        }
        StartTls::Imap => {
            let greet = read_line(s).await?;
            if !greet.starts_with("* OK") {
                bail!("bannière IMAP inattendue : {greet}");
            }
            s.write_all(b"a1 STARTTLS\r\n").await?;
            loop {
                let l = read_line(s).await?;
                if l.starts_with("a1 ") {
                    if !l.starts_with("a1 OK") {
                        bail!("STARTTLS refusé : {l}");
                    }
                    break;
                }
            }
        }
        StartTls::Pop3 => {
            let greet = read_line(s).await?;
            if !greet.starts_with("+OK") {
                bail!("bannière POP3 inattendue : {greet}");
            }
            s.write_all(b"STLS\r\n").await?;
            let r = read_line(s).await?;
            if !r.starts_with("+OK") {
                bail!("STLS refusé : {r}");
            }
        }
    }
    Ok(())
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse_du_proxy() {
        let p = ProxyConfig::parse("http://proxy.local:8080").unwrap();
        assert_eq!(
            (p.host.as_str(), p.port, p.auth.is_none()),
            ("proxy.local", 8080, true)
        );
        let p = ProxyConfig::parse("http://alice:s3cr3t@10.0.0.1:3128/").unwrap();
        assert_eq!(p.auth.as_deref(), Some("Basic YWxpY2U6czNjcjN0"));
        assert_eq!(ProxyConfig::parse("http://proxy").unwrap().port, 3128);
        assert!(ProxyConfig::parse("https://proxy:1").is_err());
        assert!(ProxyConfig::parse("http://:1").is_err());
    }

    #[test]
    fn regles_no_proxy() {
        let r: Vec<String> = vec![".exemple.local".into(), "10.0.0.5".into()];
        assert!(bypass_proxy("ldap.exemple.local", &r));
        assert!(bypass_proxy("exemple.local", &r));
        assert!(bypass_proxy("10.0.0.5", &r));
        assert!(!bypass_proxy("exemple.fr", &r));
        assert!(!bypass_proxy("pasexemple.local", &r));
        assert!(bypass_proxy("nimporte.quoi", &["*".to_string()]));
    }

    #[test]
    fn noms_des_signatures_et_cles() {
        assert_eq!(signature_name("1.2.840.113549.1.1.5"), "RSA SHA-1");
        assert_eq!(signature_name("1.2.3"), "1.2.3");
        assert_eq!(rsa_bits("RSA 1024 bits"), Some(1024));
        assert_eq!(rsa_bits("ECDSA 256 bits"), None);
    }

    #[test]
    fn messages_d_erreur() {
        let e = rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer);
        assert!(describe_tls_error(&e).contains("Autorité inconnue"));
        let e = anyhow::anyhow!("failed to lookup address information: Name or service not known");
        assert_eq!(describe_error(&e), "Nom introuvable (DNS)");
    }
}
