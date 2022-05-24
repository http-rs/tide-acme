//! `tide-acme` helps you serve HTTPS with Tide using automatic certificates, via Let's Encrypt and
//! ACME tls-alpn-01 challenges.
//!
//! To use `tide-acme`, set up HTTPS with Tide normally using `tide_rustls`, but instead of
//! specifying a certificate and key, call the `acme` method to configure automatic certificates in
//! the TLS listener:
//!
//! ```no_run
//! use tide_acme::{AcmeConfig, TideRustlsExt};
//! use tide_acme::rustls_acme::caches::DirCache;
//!
//! # async_std::task::block_on(async {
//! let mut app = tide::new();
//! app.at("/").get(|_| async { Ok("Hello TLS") });
//! app.listen(
//!     tide_rustls::TlsListener::build().addrs("0.0.0.0:443").acme(
//!         AcmeConfig::new(vec!["domain.example"])
//!             .contact_push("mailto:admin@example.org")
//!             .cache(DirCache::new("/srv/example/tide-acme-cache-dir")),
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
//! You must supply a cache via [`AcmeConfig::cache`] or one of the other cache methods. This cache
//! will keep the ACME account key and registered certificates between runs, needed to avoid
//! hitting rate limits. You can use [`rustls_acme::caches::DirCache`] for a simple filesystem
//! cache, or implement your own caching using the `rustls_acme` cache traits.
//!
//! By default, `tide-acme` will use the Let's Encrypt staging environment, which is suitable for
//! testing purposes; it produces certificates signed by a staging root so that you can verify your
//! stack is working, but those certificates will not be trusted in browsers or other HTTPS
//! clients. The staging environment has more generous rate limits for use while testing.
//!
//! When you're ready to deploy to production, you can call `.directory_lets_encrypt(true)` to
//! switch to the production Let's Encrypt environment, which produces certificates trusted in
//! browsers and other HTTPS clients. The production environment has [stricter rate
//! limits](https://letsencrypt.org/docs/rate-limits/).
//!
//! `tide-acme` builds upon [`tide-rustls`](https://crates.io/crates/tide-rustls) and
//! [`rustls-acme`](https://crates.io/crates/rustls-acme).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::Debug;

use async_std::{net::TcpStream, stream::StreamExt};
use futures_lite::io::AsyncWriteExt;
pub use rustls_acme::{self, AcmeConfig};
use tide_rustls::async_rustls::{server::TlsStream, TlsAcceptor};
use tide_rustls::rustls::Session;
use tracing::{error, info, info_span, Instrument};

/// Custom TLS acceptor that answers ACME tls-alpn-01 challenges.
pub struct AcmeTlsAcceptor(TlsAcceptor);

impl AcmeTlsAcceptor {
    /// Create a new TLS acceptor that answers ACME tls-alpn-01 challenges, based on the specified
    /// configuration.
    ///
    /// This will start a background task to manage certificates via ACME.
    pub fn new<EC: 'static + Debug, EA: 'static + Debug>(config: AcmeConfig<EC, EA>) -> Self {
        let mut state = config.state();
        let acceptor = state.acceptor();
        async_std::task::spawn(async move {
            loop {
                async {
                    match state
                        .next()
                        .await
                        .expect("AcmeState::next() always returns Some")
                    {
                        Ok(event) => info!(?event, "AcmeState::next() processed an event"),
                        Err(event) => error!(?event, "AcmeState::next() returned an error"),
                    }
                }
                .instrument(info_span!("AcmeState::next()"))
                .await
            }
        });
        Self(acceptor)
    }
}

#[async_trait::async_trait]
impl tide_rustls::CustomTlsAcceptor for AcmeTlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Option<TlsStream<TcpStream>>> {
        let mut tls = self.0.accept(stream).await?;
        match tls.get_ref().1.get_alpn_protocol() {
            Some(rustls_acme::acme::ACME_TLS_ALPN_NAME) => {
                info_span!("AcmeTlsAcceptor::accept()")
                    .in_scope(|| info!("received acme-tls/1 validation request"));
                tls.close().await?;
                Ok(None)
            }
            _ => Ok(Some(tls)),
        }
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
    fn acme<EC: 'static + Debug, EA: 'static + Debug>(self, config: AcmeConfig<EC, EA>) -> Self;
}

impl<State> TideRustlsExt for tide_rustls::TlsListenerBuilder<State> {
    fn acme<EC: 'static + Debug, EA: 'static + Debug>(self, config: AcmeConfig<EC, EA>) -> Self {
        self.tls_acceptor(std::sync::Arc::new(AcmeTlsAcceptor::new(config)))
    }
}
