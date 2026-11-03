//! Mode service : scans périodiques, tableau de bord web, API JSON et métriques Prometheus.

use crate::alert::{self, State};
use crate::config::Config;
use crate::model::{CheckResult, Status};
use crate::probe::{Prober, now_unix};
use crate::{report, scan};
use axum::extract::State as AxState;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};

const INDEX: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const STYLE: &str = include_str!("../assets/style.css");

#[derive(Default, Clone, Serialize)]
pub struct Snapshot {
    pub last_scan: Option<i64>,
    pub scanning: bool,
    pub results: Vec<CheckResult>,
}

pub struct AppState {
    pub cfg: Config,
    pub prober: Prober,
    pub snapshot: RwLock<Snapshot>,
    pub wake: Notify,
}

impl AppState {
    pub fn new(cfg: Config) -> anyhow::Result<Arc<AppState>> {
        let prober = Prober::new(&cfg.settings)?;
        Ok(Arc::new(AppState {
            cfg,
            prober,
            snapshot: RwLock::new(Snapshot::default()),
            wake: Notify::new(),
        }))
    }
}

/// Un scan complet : vérification, mise à jour de l'instantané, alertes, sauvegarde de l'état.
pub async fn run_scan(st: &AppState) {
    st.snapshot.write().await.scanning = true;
    let results = scan::scan(&st.cfg, &st.prober, &st.cfg.targets).await;
    let now = now_unix();

    if !st.cfg.alerts.is_empty() {
        let path = &st.cfg.settings.state_file;
        let mut state = State::load(path).unwrap_or_else(|e| {
            tracing::warn!("{e:#} — état remis à zéro");
            State::default()
        });
        let events = alert::plan(
            &mut state,
            &results,
            &st.cfg.alerts,
            st.cfg.settings.reminder_hours,
            now,
        );
        let sent = alert::send_all(&st.cfg.alerts, &events).await;
        if !events.is_empty() {
            tracing::info!("{sent}/{} alerte(s) envoyée(s)", events.len());
        }
        if let Err(e) = state.save(path) {
            tracing::error!("{e:#}");
        }
    }

    tracing::info!("scan terminé : {}", report::totals(&results));
    let mut snap = st.snapshot.write().await;
    snap.results = results;
    snap.last_scan = Some(now);
    snap.scanning = false;
}

/// Boucle : un scan, puis attente de l'intervalle ou d'une demande manuelle.
pub async fn scheduler(st: Arc<AppState>) {
    let every = std::time::Duration::from_secs(st.cfg.settings.interval_minutes * 60);
    loop {
        run_scan(&st).await;
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = st.wake.notified() => {}
        }
    }
}

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { asset(INDEX, "text/html; charset=utf-8") }),
        )
        .route(
            "/app.js",
            get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }),
        )
        .route(
            "/style.css",
            get(|| async { asset(STYLE, "text/css; charset=utf-8") }),
        )
        .route("/api/status", get(status))
        .route("/api/scan", post(trigger_scan))
        .route("/metrics", get(metrics))
        .route("/healthz", get(|| async { "ok" }))
        .layer(middleware::from_fn(security_headers))
        .with_state(st)
}

fn asset(body: &'static str, ctype: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, ctype),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

async fn security_headers(req: axum::extract::Request, next: middleware::Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    res
}

#[derive(Serialize)]
struct StatusBody {
    version: &'static str,
    last_scan: Option<i64>,
    scanning: bool,
    interval_minutes: u64,
    manual_scan: bool,
    totals: BTreeMap<&'static str, usize>,
    results: Vec<CheckResult>,
}

async fn status(AxState(st): AxState<Arc<AppState>>) -> Json<StatusBody> {
    let snap = st.snapshot.read().await.clone();
    let mut totals: BTreeMap<&'static str, usize> =
        Status::ALL.iter().map(|s| (s.as_str(), 0)).collect();
    for r in &snap.results {
        *totals.entry(r.status.as_str()).or_default() += 1;
    }
    Json(StatusBody {
        version: env!("CARGO_PKG_VERSION"),
        last_scan: snap.last_scan,
        scanning: snap.scanning,
        interval_minutes: st.cfg.settings.interval_minutes,
        manual_scan: st.cfg.settings.api_token.is_some(),
        totals,
        results: snap.results,
    })
}

async fn trigger_scan(AxState(st): AxState<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(expected) = st
        .cfg
        .settings
        .api_token
        .as_deref()
        .filter(|t| !t.is_empty())
    else {
        return (
            StatusCode::FORBIDDEN,
            "scan manuel désactivé (api_token absent)",
        )
            .into_response();
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_eq(given.as_bytes(), expected.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "jeton invalide").into_response();
    }
    if st.snapshot.read().await.scanning {
        return (StatusCode::CONFLICT, "scan déjà en cours").into_response();
    }
    st.wake.notify_one();
    (StatusCode::ACCEPTED, "scan demandé").into_response()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn metrics(AxState(st): AxState<Arc<AppState>>) -> Response {
    let snap = st.snapshot.read().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        report::metrics(&snap.results, snap.last_scan.unwrap_or(0)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn comparaison_de_jetons() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
