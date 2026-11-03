//! Tests de bout en bout : de vrais serveurs TLS locaux, avec des certificats fabriqués
//! pour chaque cas (CA interne, nom erroné, expiré, proxy, STARTTLS).

use certwatch::config::{Config, Settings, StartTls, Target};
use certwatch::model::{Status, Thresholds};
use certwatch::probe::Prober;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const TH: Thresholds = Thresholds {
    warning_days: 30,
    critical_days: 14,
};

struct Pki {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_pem: String,
}

impl Pki {
    fn new() -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(DnType::CommonName, "CertWatch CA de test");
        p.not_before = OffsetDateTime::now_utc() - Duration::days(30);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        let ca = p.self_signed(&ca_key).unwrap();
        Pki {
            ca_pem: ca.pem(),
            ca_params: p,
            ca_key,
        }
    }

    /// Certificat serveur pour `names`, valide de `from` à `to` jours (relatifs à maintenant).
    fn leaf(
        &self,
        names: &[&str],
        from: i64,
        to: i64,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
        p.distinguished_name.push(DnType::CommonName, names[0]);
        p.not_before = OffsetDateTime::now_utc() + Duration::days(from);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(to) + Duration::hours(1);
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let cert = p.signed_by(&key, &issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    fn ca_file(&self, dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, &self.ca_pem).unwrap();
        path
    }
}

fn acceptor(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> TlsAcceptor {
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    TlsAcceptor::from(Arc::new(cfg))
}

/// Serveur TLS direct ; renvoie son port.
async fn tls_server(acc: TlsAcceptor) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            let acc = acc.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acc.accept(s).await {
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    port
}

fn settings(ca: Option<PathBuf>) -> Settings {
    Settings {
        ca_files: ca.into_iter().collect(),
        timeout_secs: 5,
        ..Settings::default()
    }
}

fn target(port: u16, sni: &str) -> Target {
    let mut t = Target::parse(&format!("127.0.0.1:{port}")).unwrap();
    t.sni = Some(sni.to_string());
    t.name = Some("Test".into());
    t
}

#[tokio::test]
async fn ca_interne_approuvee_et_echeance_critique() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["intranet.test"], -1, 10);
    let port = tls_server(acceptor(chain, key)).await;

    let p = Prober::new(&settings(Some(pki.ca_file(&dir)))).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Critical, "{r:#?}");
    assert_eq!(r.days_remaining, Some(10));
    assert_eq!(r.tls_version.as_deref(), Some("TLS 1.3"));
    let leaf = r.leaf().unwrap();
    assert_eq!(leaf.subject, "intranet.test");
    assert_eq!(leaf.issuer, "CertWatch CA de test");
    assert_eq!(leaf.dns_names, vec!["intranet.test"]);
    assert!(leaf.key.starts_with("ECDSA"));
    assert!(r.issues.is_empty(), "{:?}", r.issues);

    // Seuils plus bas : le même certificat est « OK »
    let r = p
        .check(
            &target(port, "intranet.test"),
            Thresholds {
                warning_days: 7,
                critical_days: 3,
            },
        )
        .await;
    assert_eq!(r.status, Status::Ok);
}

#[tokio::test]
async fn ca_inconnue_donne_invalide() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let (chain, key) = pki.leaf(&["intranet.test"], -1, 200);
    let port = tls_server(acceptor(chain, key)).await;

    let p = Prober::new(&settings(None)).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Invalid);
    assert!(r.message.contains("Autorité inconnue"), "{}", r.message);
    // La chaîne est quand même lue : on sait ce qui est déployé.
    assert_eq!(r.days_remaining, Some(200));
}

#[tokio::test]
async fn nom_qui_ne_correspond_pas() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["autre.test"], -1, 200);
    let port = tls_server(acceptor(chain, key)).await;

    let p = Prober::new(&settings(Some(pki.ca_file(&dir)))).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Invalid);
    assert!(r.message.contains("ne couvre pas"), "{}", r.message);
}

#[tokio::test]
async fn certificat_expire() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["intranet.test"], -90, -3);
    let port = tls_server(acceptor(chain, key)).await;

    let p = Prober::new(&settings(Some(pki.ca_file(&dir)))).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Expired);
    assert_eq!(r.days_remaining, Some(-3));
    assert!(r.message.starts_with("Expiré depuis 3"), "{}", r.message);
}

#[tokio::test]
async fn certificat_pas_encore_valide() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["intranet.test"], 5, 300);
    let port = tls_server(acceptor(chain, key)).await;

    let p = Prober::new(&settings(Some(pki.ca_file(&dir)))).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Expired);
    assert_eq!(r.message, "Certificat pas encore valide");
}

#[tokio::test]
async fn port_ferme() {
    certwatch::install_crypto();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let p = Prober::new(&settings(None)).unwrap();
    let r = p.check(&target(port, "x.test"), TH).await;
    assert_eq!(r.status, Status::Error);
    assert!(r.message.contains("refusée"), "{}", r.message);
}

#[tokio::test]
async fn delai_depasse() {
    certwatch::install_crypto();
    // Accepte la connexion TCP mais ne répond jamais.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            keep.push(s);
        }
    });
    let p = Prober::new(&Settings {
        timeout_secs: 1,
        ..Settings::default()
    })
    .unwrap();
    let r = p.check(&target(port, "x.test"), TH).await;
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.message, "Délai dépassé (1 s)");
}

#[tokio::test]
async fn passage_par_un_proxy_connect() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["intranet.test"], -1, 120);
    let port = tls_server(acceptor(chain, key)).await;

    let seen = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = l.local_addr().unwrap().port();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                let mut first = String::new();
                r.read_line(&mut first).await.unwrap();
                let mut auth_ok = false;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).await.unwrap();
                    if h.starts_with("Proxy-Authorization: Basic ") {
                        auth_ok = true;
                    }
                    if h == "\r\n" {
                        break;
                    }
                }
                let dest = first.split_whitespace().nth(1).unwrap().to_string();
                assert!(first.starts_with("CONNECT ") && auth_ok);
                seen.fetch_add(1, Ordering::SeqCst);
                let mut client = r.into_inner();
                let mut up = TcpStream::connect(dest).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
            });
        }
    });

    let mut s = settings(Some(pki.ca_file(&dir)));
    s.proxy = Some(format!("http://equipe:secret@127.0.0.1:{pport}"));
    let p = Prober::new(&s).unwrap();
    let r = p.check(&target(port, "intranet.test"), TH).await;
    assert_eq!(r.status, Status::Ok, "{r:#?}");
    assert_eq!(seen.load(Ordering::SeqCst), 1);

    // no_proxy : connexion directe, le proxy n'est pas sollicité
    s.no_proxy = vec!["127.0.0.1".into()];
    let p = Prober::new(&s).unwrap();
    assert_eq!(
        p.check(&target(port, "intranet.test"), TH).await.status,
        Status::Ok
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn starttls_smtp() {
    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (chain, key) = pki.leaf(&["smtp.test"], -1, 60);
    let acc = acceptor(chain, key);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(b"220 smtp.test ESMTP\r\n").await.unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"EHLO "));
        s.write_all(b"250-smtp.test\r\n250-SIZE 1000\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"STARTTLS\r\n");
        s.write_all(b"220 2.0.0 Ready\r\n").await.unwrap();
        let mut tls = acc.accept(s).await.unwrap();
        let _ = tls.shutdown().await;
    });

    let p = Prober::new(&settings(Some(pki.ca_file(&dir)))).unwrap();
    let mut t = target(port, "smtp.test");
    t.starttls = Some(StartTls::Smtp);
    let r = p.check(&t, TH).await;
    assert_eq!(r.status, Status::Ok, "{r:#?}");
    assert_eq!(r.days_remaining, Some(60));
}

#[tokio::test]
async fn scan_complet_et_api_du_tableau_de_bord() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    certwatch::install_crypto();
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let (c1, k1) = pki.leaf(&["a.test"], -1, 100);
    let (c2, k2) = pki.leaf(&["b.test"], -1, 5);
    let p1 = tls_server(acceptor(c1, k1)).await;
    let p2 = tls_server(acceptor(c2, k2)).await;

    let mut s = settings(Some(pki.ca_file(&dir)));
    s.state_file = dir.path().join("etat.json");
    s.api_token = Some("jeton-de-test".into());
    let cfg = Config {
        settings: s,
        alerts: vec![],
        targets: vec![target(p1, "a.test"), {
            let mut t = target(p2, "b.test");
            t.name = Some("Critique".into());
            t
        }],
    };
    cfg.validate().unwrap();
    let st = certwatch::server::AppState::new(cfg).unwrap();
    certwatch::server::run_scan(&st).await;
    let app = certwatch::server::router(st.clone());

    let res = app
        .clone()
        .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(j["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        j["results"][0]["name"], "Critique",
        "le plus urgent en premier"
    );
    assert_eq!(j["totals"]["critical"], 1);
    assert_eq!(j["totals"]["ok"], 1);

    let res = app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let m = String::from_utf8(
        axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(m.contains("certwatch_targets 2"));
    assert!(m.contains(&format!("port=\"{p2}\"}} 5")));

    let res = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(Request::post("/api/scan").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .oneshot(
            Request::post("/api/scan")
                .header("authorization", "Bearer jeton-de-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
}
