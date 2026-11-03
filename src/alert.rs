//! Alertes : on ne prévient qu'aux changements de statut (plus un rappel périodique),
//! pour ne pas noyer l'équipe sous des messages identiques.

use crate::config::{AlertConfig, AlertKind};
use crate::model::{CheckResult, Status};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub targets: HashMap<String, TargetState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetState {
    pub status: Status,
    pub since: i64,
    /// Dernière alerte envoyée, par canal (indice dans la liste des alertes).
    #[serde(default)]
    pub alerted: HashMap<usize, i64>,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t)
                .with_context(|| format!("état illisible : {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", path.display())),
        }
    }

    /// Écriture atomique : fichier temporaire puis renommage.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path).with_context(|| format!("écriture de {}", path.display()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// Nouveau problème, ou problème qui change de nature.
    Problem,
    /// Retour sous le seuil d'alerte.
    Recovered,
    /// Le problème persiste.
    Reminder,
}

/// Faut-il prévenir ce canal ?
pub fn decide(
    previous: Option<Status>,
    current: Status,
    last_alert: Option<i64>,
    now: i64,
    min_status: Status,
    reminder_hours: u64,
) -> Option<EventKind> {
    let serious = current >= min_status;
    match previous {
        None => serious.then_some(EventKind::Problem),
        Some(p) if p != current => {
            if serious {
                Some(EventKind::Problem)
            } else if p >= min_status {
                Some(EventKind::Recovered)
            } else {
                None
            }
        }
        Some(_) => {
            let due = reminder_hours > 0
                && last_alert.is_none_or(|t| now - t >= reminder_hours as i64 * 3600);
            (serious && due).then_some(EventKind::Reminder)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub channel: usize,
    pub kind: EventKind,
    pub previous: Option<Status>,
    pub result: CheckResult,
}

/// Compare les résultats à l'état précédent, met l'état à jour et renvoie les alertes à envoyer.
pub fn plan(
    state: &mut State,
    results: &[CheckResult],
    alerts: &[AlertConfig],
    reminder_hours: u64,
    now: i64,
) -> Vec<Event> {
    let mut events = Vec::new();
    for r in results {
        let key = r.key();
        let prev = state.targets.get(&key).cloned();
        let entry = state.targets.entry(key).or_insert_with(|| TargetState {
            status: r.status,
            since: now,
            alerted: HashMap::new(),
        });
        for (i, a) in alerts.iter().enumerate() {
            if !a.tags.is_empty() && !a.tags.iter().any(|t| r.tags.contains(t)) {
                continue;
            }
            let last = prev.as_ref().and_then(|p| p.alerted.get(&i).copied());
            if let Some(kind) = decide(
                prev.as_ref().map(|p| p.status),
                r.status,
                last,
                now,
                a.min_status,
                reminder_hours,
            ) {
                entry.alerted.insert(i, now);
                events.push(Event {
                    channel: i,
                    kind,
                    previous: prev.as_ref().map(|p| p.status),
                    result: r.clone(),
                });
            }
        }
        if prev.as_ref().is_some_and(|p| p.status != r.status) {
            entry.since = now;
        }
        entry.status = r.status;
    }
    events
}

pub fn format_date(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|d| {
            d.format(time::macros::format_description!("[day]/[month]/[year]"))
                .ok()
        })
        .unwrap_or_else(|| "?".into())
}

fn icon(s: Status) -> &'static str {
    match s {
        Status::Ok => "✅",
        Status::Warning => "🟠",
        Status::Critical => "🔴",
        _ => "⛔",
    }
}

/// Texte court commun à tous les canaux.
pub fn summary(e: &Event) -> String {
    let r = &e.result;
    let head = match e.kind {
        EventKind::Recovered => "Rétabli".to_string(),
        EventKind::Reminder => format!("Rappel — {}", r.status.label_fr()),
        EventKind::Problem => r.status.label_fr().to_string(),
    };
    let when = r
        .expires_at
        .map(|t| format!(" (échéance le {})", format_date(t)))
        .unwrap_or_default();
    format!(
        "{} [CertWatch] {} ({}) : {} — {}{}",
        icon(r.status),
        r.name,
        r.key(),
        head,
        r.message,
        when
    )
}

pub fn payload(kind: AlertKind, e: &Event) -> Value {
    let r = &e.result;
    let text = summary(e);
    match kind {
        AlertKind::Webhook => json!({
            "source": "certwatch",
            "event": e.kind,
            "target": r.name,
            "host": r.host,
            "port": r.port,
            "status": r.status,
            "previous_status": e.previous,
            "days_remaining": r.days_remaining,
            "expires_at": r.expires_at,
            "message": r.message,
            "issues": r.issues,
            "tags": r.tags,
            "text": text,
        }),
        AlertKind::Slack => json!({ "text": text }),
        AlertKind::Teams => {
            let mut facts = vec![
                json!({"title": "Cible", "value": r.key()}),
                json!({"title": "Statut", "value": r.status.label_fr()}),
            ];
            if let Some(d) = r.days_remaining {
                facts.push(json!({"title": "Jours restants", "value": d.to_string()}));
            }
            if let Some(t) = r.expires_at {
                facts.push(json!({"title": "Échéance", "value": format_date(t)}));
            }
            json!({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true,
                             "text": format!("{} {}", icon(r.status), r.name)},
                            {"type": "TextBlock", "wrap": true, "text": r.message},
                            {"type": "FactSet", "facts": facts}
                        ]
                    }
                }]
            })
        }
    }
}

/// Envoie les alertes ; une erreur d'envoi est journalisée sans interrompre les autres.
pub async fn send_all(alerts: &[AlertConfig], events: &[Event]) -> usize {
    if events.is_empty() {
        return 0;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("certwatch/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("client HTTP : {e}");
            return 0;
        }
    };
    let mut sent = 0;
    for e in events {
        let a = &alerts[e.channel];
        let body = payload(a.kind, e);
        match client.post(&a.url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => sent += 1,
            Ok(resp) => {
                tracing::warn!("alerte refusée ({}) pour {}", resp.status(), e.result.key())
            }
            Err(err) => tracing::warn!("alerte non envoyée pour {} : {err}", e.result.key()),
        }
    }
    sent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(status: Status, tags: &[&str]) -> CheckResult {
        CheckResult {
            name: "Intranet".into(),
            host: "intranet.exemple.fr".into(),
            port: 443,
            server_name: "test".into(),
            status,
            days_remaining: Some(9),
            expires_at: Some(1_800_000_000),
            message: "Expire dans 9 jour(s)".into(),
            issues: vec![],
            tls_version: None,
            cipher_suite: None,
            chain: vec![],
            tags: tags.iter().map(|s| s.to_string()).collect(),
            checked_at: 0,
            duration_ms: 0,
        }
    }

    fn canal(min: Status, tags: &[&str]) -> AlertConfig {
        AlertConfig {
            kind: AlertKind::Webhook,
            url: "https://exemple.invalid/hook".into(),
            min_status: min,
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn decisions() {
        use EventKind::*;
        use Status::*;
        // première fois
        assert_eq!(decide(None, Ok, None, 0, Warning, 24), None);
        assert_eq!(decide(None, Critical, None, 0, Warning, 24), Some(Problem));
        // changement
        assert_eq!(
            decide(Some(Warning), Critical, Some(0), 10, Warning, 24),
            Some(Problem)
        );
        assert_eq!(
            decide(Some(Critical), Ok, Some(0), 10, Warning, 24),
            Some(Recovered)
        );
        assert_eq!(decide(Some(Ok), Warning, None, 10, Critical, 24), None);
        assert_eq!(decide(Some(Warning), Ok, None, 10, Critical, 24), None);
        // stable : rappel seulement après le délai
        assert_eq!(
            decide(Some(Critical), Critical, Some(0), 3600, Warning, 24),
            None
        );
        assert_eq!(
            decide(Some(Critical), Critical, Some(0), 24 * 3600, Warning, 24),
            Some(Reminder)
        );
        assert_eq!(
            decide(Some(Critical), Critical, Some(0), 99 * 3600, Warning, 0),
            None
        );
        assert_eq!(decide(Some(Ok), Ok, None, 99 * 3600, Warning, 24), None);
    }

    #[test]
    fn plan_met_a_jour_l_etat_et_filtre_les_etiquettes() {
        let mut st = State::default();
        let alerts = vec![
            canal(Status::Warning, &[]),
            canal(Status::Warning, &["prod"]),
        ];
        let ev = plan(
            &mut st,
            &[res(Status::Critical, &["interne"])],
            &alerts,
            24,
            100,
        );
        assert_eq!(ev.len(), 1, "le canal « prod » ne concerne pas cette cible");
        assert_eq!(ev[0].channel, 0);
        assert_eq!(
            st.targets["intranet.exemple.fr:443"].status,
            Status::Critical
        );

        // même statut une heure plus tard : silence
        let ev = plan(
            &mut st,
            &[res(Status::Critical, &["interne"])],
            &alerts,
            24,
            3700,
        );
        assert!(ev.is_empty());

        // retour à la normale : prévenu
        let ev = plan(&mut st, &[res(Status::Ok, &["interne"])], &alerts, 24, 7300);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Recovered);
        assert_eq!(st.targets["intranet.exemple.fr:443"].since, 7300);
    }

    #[test]
    fn etat_sauvegarde_et_relu() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sous/etat.json");
        let mut st = State::default();
        plan(
            &mut st,
            &[res(Status::Warning, &[])],
            &[canal(Status::Warning, &[])],
            24,
            5,
        );
        st.save(&path).unwrap();
        let back = State::load(&path).unwrap();
        assert_eq!(back.targets["intranet.exemple.fr:443"].alerted[&0], 5);
        assert!(
            State::load(&dir.path().join("absent.json"))
                .unwrap()
                .targets
                .is_empty()
        );
    }

    #[test]
    fn formats_des_messages() {
        let e = Event {
            channel: 0,
            kind: EventKind::Problem,
            previous: Some(Status::Warning),
            result: res(Status::Critical, &[]),
        };
        let s = summary(&e);
        assert!(
            s.contains("Critique")
                && s.contains("intranet.exemple.fr:443")
                && s.contains("15/01/2027")
        );
        let w = payload(AlertKind::Webhook, &e);
        assert_eq!(w["status"], "critical");
        assert_eq!(w["previous_status"], "warning");
        assert_eq!(payload(AlertKind::Slack, &e)["text"], s);
        let t = payload(AlertKind::Teams, &e);
        assert_eq!(t["attachments"][0]["content"]["type"], "AdaptiveCard");
    }
}
