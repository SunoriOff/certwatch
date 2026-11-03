//! CertWatch — surveillance des certificats TLS.
//!
//! Le binaire `certwatch` s'appuie sur cette bibliothèque ; les modules sont publics
//! pour les tests d'intégration et pour une réutilisation éventuelle.

pub mod alert;
pub mod config;
pub mod model;
pub mod probe;
pub mod report;
pub mod scan;
pub mod server;

/// À appeler une fois au démarrage : rustls et reqwest utilisent alors `ring`.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
