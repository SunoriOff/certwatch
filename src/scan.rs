//! Vérification de toutes les cibles en parallèle, avec une limite de simultanéité.

use crate::config::{Config, Target};
use crate::model::CheckResult;
use crate::probe::Prober;
use futures::stream::{self, StreamExt};

/// Vérifie toutes les cibles ; résultats triés du plus urgent au moins urgent.
pub async fn scan(cfg: &Config, prober: &Prober, targets: &[Target]) -> Vec<CheckResult> {
    let mut results: Vec<CheckResult> = stream::iter(targets.iter().cloned())
        .map(|t| {
            let p = prober.clone();
            let th = t.thresholds(&cfg.settings);
            async move { p.check(&t, th).await }
        })
        .buffer_unordered(cfg.settings.concurrency)
        .collect()
        .await;
    sort_results(&mut results);
    results
}

/// Statut le plus grave d'abord, puis échéance la plus proche, puis nom.
pub fn sort_results(results: &mut [CheckResult]) {
    results.sort_by(|a, b| {
        b.status
            .cmp(&a.status)
            .then(
                a.days_remaining
                    .unwrap_or(i64::MAX)
                    .cmp(&b.days_remaining.unwrap_or(i64::MAX)),
            )
            .then(a.name.cmp(&b.name))
    });
}
