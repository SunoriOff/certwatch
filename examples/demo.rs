//! Démo autonome : lance six faux services TLS locaux (un par cas de figure) et le tableau
//! de bord CertWatch sur http://127.0.0.1:8088/.
//!
//!     cargo run --example demo
//!
//! Aucun accès réseau : tout se passe sur 127.0.0.1, avec une CA générée à la volée.

use certwatch::config::{Config, Settings, Target};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn ca(name: &str) -> (CertificateParams, KeyPair, String) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, name);
    p.distinguished_name
        .push(DnType::OrganizationName, "Exemple SA");
    p.not_before = OffsetDateTime::now_utc() - Duration::days(400);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(3000);
    let pem = p.self_signed(&key).unwrap().pem();
    (p, key, pem)
}

async fn serve_tls(
    ca: &(CertificateParams, KeyPair, String),
    name: &str,
    from: i64,
    to: i64,
) -> u16 {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.not_before = OffsetDateTime::now_utc() + Duration::days(from);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(to) + Duration::hours(2);
    let cert = p
        .signed_by(&key, &Issuer::from_params(&ca.0, &ca.1))
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = acc.accept(s).await {
                    let _ = t.shutdown().await;
                }
            });
        }
    });
    port
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    certwatch::install_crypto();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let interne = ca("Exemple SA — CA interne");
    let inconnue = ca("CA d'un ancien prestataire");
    let dir = tempfile::tempdir()?;
    let ca_path = dir.path().join("ca-interne.pem");
    std::fs::write(&ca_path, &interne.2)?;

    // (nom affiché, nom du certificat, nom attendu, CA, début, fin, étiquettes)
    let cases = [
        (
            "Portail RH",
            "rh.exemple.local",
            "rh.exemple.local",
            &interne,
            -60,
            240,
            "prod",
        ),
        (
            "Messagerie web",
            "mail.exemple.local",
            "mail.exemple.local",
            &interne,
            -300,
            24,
            "prod",
        ),
        (
            "Intranet",
            "intranet.exemple.local",
            "intranet.exemple.local",
            &interne,
            -360,
            6,
            "prod",
        ),
        (
            "API partenaires",
            "api.exemple.local",
            "api.exemple.local",
            &interne,
            -400,
            -2,
            "prod",
        ),
        (
            "Console de sauvegarde",
            "backup-old.exemple.local",
            "sauvegarde.exemple.local",
            &interne,
            -30,
            330,
            "interne",
        ),
        (
            "Ancien extranet",
            "extranet.exemple.local",
            "extranet.exemple.local",
            &inconnue,
            -100,
            180,
            "interne",
        ),
        (
            "Wiki technique",
            "wiki.exemple.local",
            "wiki.exemple.local",
            &interne,
            -20,
            345,
            "interne",
        ),
    ];
    let mut targets = Vec::new();
    for (label, cert_name, sni, ca, from, to, tag) in cases {
        let port = serve_tls(ca, cert_name, from, to).await;
        let mut t = Target::parse(&format!("127.0.0.1:{port}"))?;
        t.name = Some(label.into());
        t.sni = Some(sni.into());
        t.tags = vec![tag.into()];
        targets.push(t);
    }

    let cfg = Config {
        settings: Settings {
            ca_files: vec![ca_path],
            state_file: dir.path().join("etat.json"),
            api_token: Some("demo".into()),
            ..Settings::default()
        },
        alerts: vec![],
        targets,
    };
    cfg.validate()?;
    let st = certwatch::server::AppState::new(cfg)?;
    tokio::spawn(certwatch::server::scheduler(st.clone()));
    let listen = std::env::var("CERTWATCH_DEMO_LISTEN").unwrap_or_else(|_| "127.0.0.1:8088".into());
    let l = TcpListener::bind(&listen).await?;
    println!(
        "\n  Démo CertWatch : http://{listen}/   (jeton du bouton « Relancer un scan » : demo)\n"
    );
    axum::serve(l, certwatch::server::router(st)).await?;
    Ok(())
}
