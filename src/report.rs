//! Sorties : tableau pour le terminal, JSON, CSV et métriques Prometheus.

use crate::alert::format_date;
use crate::model::{CheckResult, Status};
use std::fmt::Write;

pub fn table(results: &[CheckResult], color: bool) -> String {
    let headers = ["STATUT", "CIBLE", "HÔTE", "JOURS", "ÉCHÉANCE", "DÉTAIL"];
    let rows: Vec<[String; 6]> = results
        .iter()
        .map(|r| {
            [
                r.status.label_fr().to_string(),
                r.name.clone(),
                r.key(),
                r.days_remaining
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "—".into()),
                r.expires_at.map(format_date).unwrap_or_else(|| "—".into()),
                r.message.clone(),
            ]
        })
        .collect();
    let mut widths = headers.map(|h| h.chars().count());
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let pad = |s: &str, w: usize| format!("{s}{}", " ".repeat(w.saturating_sub(s.chars().count())));
    let mut out = String::new();
    let line: Vec<String> = headers.iter().zip(widths).map(|(h, w)| pad(h, w)).collect();
    let _ = writeln!(out, "{}", line.join("  ").trim_end());
    for (row, r) in rows.iter().zip(results) {
        let cells: Vec<String> = row.iter().zip(widths).map(|(c, w)| pad(c, w)).collect();
        let mut text = cells.join("  ").trim_end().to_string();
        if color {
            let code = match r.status {
                Status::Ok => "32",
                Status::Warning => "33",
                Status::Critical => "31",
                _ => "1;31",
            };
            let first = cells[0].clone();
            text = text.replacen(&first, &format!("\x1b[{code}m{first}\x1b[0m"), 1);
        }
        let _ = writeln!(out, "{text}");
        for issue in r.issues.iter().filter(|i| **i != r.message) {
            let _ = writeln!(out, "{}  ↳ {issue}", " ".repeat(widths[0]));
        }
    }
    let _ = writeln!(out, "\n{}", totals(results));
    out
}

pub fn totals(results: &[CheckResult]) -> String {
    let count = |s: Status| results.iter().filter(|r| r.status == s).count();
    let mut parts = vec![format!("{} cible(s)", results.len())];
    for s in Status::ALL {
        let n = count(s);
        if n > 0 {
            parts.push(format!("{n} {}", s.label_fr().to_lowercase()));
        }
    }
    parts.join(" · ")
}

pub fn csv(results: &[CheckResult]) -> String {
    let esc = |s: &str| {
        if s.contains([';', '"', '\n']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    };
    let mut out = String::from("statut;cible;hote;port;jours_restants;echeance;emetteur;message\n");
    for r in results {
        let _ = writeln!(
            out,
            "{};{};{};{};{};{};{};{}",
            r.status,
            esc(&r.name),
            esc(&r.host),
            r.port,
            r.days_remaining.map(|d| d.to_string()).unwrap_or_default(),
            r.expires_at.map(format_date).unwrap_or_default(),
            esc(&r.leaf().map(|c| c.issuer.clone()).unwrap_or_default()),
            esc(&r.message)
        );
    }
    out
}

fn label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

/// Format texte d'exposition Prometheus.
pub fn metrics(results: &[CheckResult], last_scan: i64) -> String {
    let mut o = String::new();
    o.push_str(
        "# HELP certwatch_days_remaining Jours avant l'expiration effective de la chaîne.\n",
    );
    o.push_str("# TYPE certwatch_days_remaining gauge\n");
    for r in results {
        if let Some(d) = r.days_remaining {
            let _ = writeln!(
                o,
                "certwatch_days_remaining{{name=\"{}\",host=\"{}\",port=\"{}\"}} {d}",
                label(&r.name),
                label(&r.host),
                r.port
            );
        }
    }
    o.push_str("# HELP certwatch_status Statut courant (1 pour le statut actif).\n");
    o.push_str("# TYPE certwatch_status gauge\n");
    for r in results {
        for s in Status::ALL {
            let _ = writeln!(
                o,
                "certwatch_status{{name=\"{}\",host=\"{}\",port=\"{}\",status=\"{s}\"}} {}",
                label(&r.name),
                label(&r.host),
                r.port,
                u8::from(r.status == s)
            );
        }
    }
    o.push_str(
        "# HELP certwatch_targets Nombre de cibles surveillées.\n# TYPE certwatch_targets gauge\n",
    );
    let _ = writeln!(o, "certwatch_targets {}", results.len());
    o.push_str("# HELP certwatch_last_scan_timestamp_seconds Fin du dernier scan.\n# TYPE certwatch_last_scan_timestamp_seconds gauge\n");
    let _ = writeln!(o, "certwatch_last_scan_timestamp_seconds {last_scan}");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, status: Status, days: Option<i64>) -> CheckResult {
        CheckResult {
            name: name.into(),
            host: format!("{}.exemple.fr", name.to_lowercase()),
            port: 443,
            server_name: "test".into(),
            status,
            days_remaining: days,
            expires_at: days.map(|d| 1_800_000_000 + d),
            message: "m".into(),
            issues: vec!["Autorité inconnue".into()],
            tls_version: None,
            cipher_suite: None,
            chain: vec![],
            tags: vec![],
            checked_at: 0,
            duration_ms: 0,
        }
    }

    #[test]
    fn tableau_aligne_et_totaux() {
        let v = vec![
            r("Intranet", Status::Critical, Some(9)),
            r("Web", Status::Ok, Some(80)),
        ];
        let t = table(&v, false);
        assert!(t.lines().next().unwrap().starts_with("STATUT"));
        assert!(t.contains("↳ Autorité inconnue"));
        assert!(t.contains("2 cible(s) · 1 ok · 1 critique"));
        assert!(!t.contains('\x1b'));
        assert!(table(&v, true).contains("\x1b[31m"));
    }

    #[test]
    fn csv_echappe() {
        let mut x = r("A", Status::Ok, Some(1));
        x.name = "Site; \"public\"".into();
        let c = csv(&[x]);
        assert!(c.contains("\"Site; \"\"public\"\"\""));
    }

    #[test]
    fn metriques_prometheus() {
        let m = metrics(
            &[
                r("Web", Status::Warning, Some(20)),
                r("Ko", Status::Error, None),
            ],
            42,
        );
        assert!(m.contains(
            "certwatch_days_remaining{name=\"Web\",host=\"web.exemple.fr\",port=\"443\"} 20"
        ));
        assert!(m.contains("status=\"warning\"} 1"));
        assert!(m.contains("status=\"ok\"} 0"));
        assert!(!m.contains("certwatch_days_remaining{name=\"Ko\""));
        assert!(m.contains("certwatch_targets 2"));
        assert!(m.contains("certwatch_last_scan_timestamp_seconds 42"));
    }
}
