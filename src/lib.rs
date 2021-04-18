//! `tide-acme` helps you serve HTTPS with Tide using automatic certificates, via Let's Encrypt and
//! ACME tls-alpn-01 challenges.
//!
//! To use `tide-acme`, set up HTTPS with Tide normally using `tide_rustls`, but instead of
//! specifying a certificate and key, call the `acme` method to configure automatic certificates in
//! the TLS listener:
//!
//! ```no_run
//! use tide_acme::{AcmeConfig, TideRustlsExt};
//!
//! # async_std::task::block_on(async {
//! let mut app = tide::new();
//! app.at("/").get(|_| async { Ok("Hello TLS") });
//! app.listen(
//!     tide_rustls::TlsListener::build().addrs("0.0.0.0:443").acme(
//!         AcmeConfig::new()
//!             .domains(vec!["domain.example".to_string()])
//!             .contact_email("admin@example.org")
//!             .cache_dir("/srv/example/tide-acme-cache-dir"),
//!     ),
//! )
//! .await?;
//! # tide::Result::Ok(())
//! # });
//! ```
//!
//! This will configure the TLS stack to obtain a certificate for the domain `domain.example`,
//! which must be a domain for which your Tide server handles HTTPS traffic.
//!
//! On initial startup, your server will register a certificate via Let's Encrypt. Let's Encrypt
//! will verify your server's control of the domain via an [ACME tls-alpn-01
//! challenge](https://tools.ietf.org/html/rfc8737), which the TLS listener configured by
//! `tide-acme` will respond to.
//!
//! You must supply a persistent cache directory via [`AcmeConfig::cache_dir`]. This cache
//! directory will keep the ACME account key and registered certificates between runs, needed to
//! avoid hitting rate limits.
//!
//! By default, `tide-acme` will use the Let's Encrypt staging environment, which is suitable for
//! testing purposes; it produces certificates signed by a staging root so that you can verify your
//! stack is working, but those certificates will not be trusted in browsers or other HTTPS
//! clients. The staging environment has more generous rate limits for use while testing.
//!
//! When you're ready to deploy to production, you can call the [`AcmeConfig::production`] method
//! to switch to the production Let's Encrypt environment, which produces certificates trusted in
//! browsers and other HTTPS clients. The production environment has [stricter rate
//! limits](https://letsencrypt.org/docs/rate-limits/).
//!
//! `tide-acme` builds upon [`tide-rustls`](https://crates.io/crates/tide-rustls) and
//! [`rustls-acme`](https://crates.io/crates/rustls-acme).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_std::net::TcpStream;
use tide_rustls::async_rustls::server::TlsStream;
use tide_rustls::rustls::{self, ServerConfig};

enum Environment {
    Staging,
    Production,
    Custom(&'static str),
}

/// Configuration for registering a certificate via ACME.
pub struct AcmeConfig {
    domains: Option<Vec<String>>,
    contact: Option<String>,
    cache_dir: Option<PathBuf>,
    environment: Environment,
    server_config: Option<ServerConfig>,
}

impl AcmeConfig {
    /// Create a new configuration builder to register a certificate.
    ///
    /// By default, this registers certificates in the Let's Encrypt staging environment.
    pub fn new() -> Self {
        Self {
            domains: None,
            contact: None,
            cache_dir: None,
            environment: Environment::Staging,
            server_config: None,
        }
    }

    /// Register a certificate for the specified domains.
    ///
    /// The list of domains must not be empty.
    pub fn domains(mut self, domains: Vec<String>) -> Self {
        self.domains = Some(domains);
        self
    }

    /// Set the contact email for the ACME account.
    ///
    /// ACME implementations such as Let's Encrypt use this email to contact account owners to
    /// notify them of potential issues or changes to the service. You should always set this,
    /// especially if using production infrastructure.
    ///
    /// Domains such as @example.org will be rejected, so that they can be used in documentation.
    pub fn contact_email(mut self, email: &str) -> Self {
        self.contact = Some(format!("mailto:{}", email));
        self
    }

    /// Register the certificate in the Let's Encrypt production environment.
    ///
    /// If not set, defaults to the Let's Encrypt staging environment.
    ///
    /// Note that the production environment has [strict rate
    /// limits](https://letsencrypt.org/docs/rate-limits/). Use the default staging environment for
    /// test purposes.
    pub fn production(mut self) -> Self {
        self.environment = Environment::Production;
        self
    }

    /// Set the ACME API URL to use to register the certificate.
    ///
    /// If not set, defaults to the Let's Encrypt staging environment.
    pub fn acme_api_url(mut self, environment: &'static str) -> Self {
        self.environment = Environment::Custom(environment);
        self
    }

    /// Set the persistent cache directory to remember registered certificates between runs.
    /// (Required.)
    ///
    /// Keep this directory private and secure.
    pub fn cache_dir(mut self, cache_dir: impl AsRef<Path>) -> Self {
        self.cache_dir = Some(cache_dir.as_ref().to_path_buf());
        self
    }

    /// Set the TLS server configuration.
    ///
    /// If not set, uses the rustls default configuration.
    pub fn server_config(mut self, server_config: ServerConfig) -> Self {
        self.server_config = Some(server_config);
        self
    }
}

/// Custom TLS acceptor that answers ACME tls-alpn-01 challenges.
pub struct AcmeTlsAcceptor(rustls_acme::TlsAcceptor);

impl AcmeTlsAcceptor {
    /// Create a new TLS acceptor that answers ACME tls-alpn-01 challenges, based on the specified
    /// configuration.
    ///
    /// This will start a background task to manage certificates via ACME.
    pub fn new(config: AcmeConfig) -> Self {
        let domains = config.domains.expect("AcmeConfig must set domains");
        assert!(!domains.is_empty());
        let cache_dir = config.cache_dir.expect("AcmeConfig must set cache_dir");
        let environment = match config.environment {
            Environment::Staging => rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY,
            Environment::Production => rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            Environment::Custom(environment) => environment,
        };
        let server_config = config
            .server_config
            .unwrap_or_else(|| ServerConfig::new(rustls::NoClientAuth::new()));

        let resolver = rustls_acme::ResolvesServerCertUsingAcme::with_contact(&config.contact);
        let acceptor = rustls_acme::TlsAcceptor::new(server_config, resolver.clone());
        async_std::task::spawn(async move {
            resolver.run(environment, domains, Some(cache_dir)).await;
        });

        Self(acceptor)
    }
}

#[async_trait::async_trait]
impl tide_rustls::CustomTlsAcceptor for AcmeTlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Option<TlsStream<TcpStream>>> {
        self.0.accept(stream).await
    }
}

/// Extension trait for [`tide_rustls::TlsListenerBuilder`]
///
/// With this trait imported, `TlsListenerBuilder` will have an `acme` method to set up a custom
/// TLS acceptor that answers ACME tls-alpn-01 challenges.
pub trait TideRustlsExt {
    /// Set up a custom TLS acceptor that answers ACME tls-alpn-01 challenges, using the specified
    /// configuration.
    ///
    /// This creates an [`AcmeTlsAcceptor`], which will start a background task to manage
    /// certificates via ACME.
    fn acme(self, config: AcmeConfig) -> Self;
}

impl<State> TideRustlsExt for tide_rustls::TlsListenerBuilder<State> {
    fn acme(self, config: AcmeConfig) -> Self {
        self.tls_acceptor(Arc::new(AcmeTlsAcceptor::new(config)))
    }
}
