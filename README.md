`tide-acme` helps you serve HTTPS with Tide using automatic certificates, via
Let's Encrypt and ACME tls-alpn-01 challenges.

[Documentation](https://docs.rs/tide-acme)

To use `tide-acme`, set up HTTPS with Tide normally using `tide_rustls`, but
instead of specifying a certificate and key, call the `acme` method to
configure automatic certificates in the TLS listener:

```rust
use tide_acme::{AcmeConfig, TideRustlsExt};
use tide_acme::rustls_acme::caches::DirCache;

let mut app = tide::new();
app.at("/").get(|_| async { Ok("Hello TLS") });
app.listen(
    tide_rustls::TlsListener::build().addrs("0.0.0.0:443").acme(
        AcmeConfig::new(vec!["domain.example"])
            .contact_push("mailto:admin@example.org")
            .cache(DirCache::new("/srv/example/tide-acme-cache-dir")),
    ),
)
.await?;
```

This will configure the TLS stack to obtain a certificate for the domain
`domain.example`, which must be a domain for which your Tide server handles
HTTPS traffic.

On initial startup, your server will register a certificate via Let's Encrypt.
Let's Encrypt will verify your server's control of the domain via an [ACME
tls-alpn-01 challenge](https://tools.ietf.org/html/rfc8737), which the TLS
listener configured by `tide-acme` will respond to.

You must supply a cache via [`AcmeConfig::cache`] or one of the other cache
methods. This cache will keep the ACME account key and registered certificates
between runs, needed to avoid hitting rate limits. You can use
[`rustls_acme::caches::DirCache`] for a simple filesystem cache, or implement
your own caching using the `rustls_acme` cache traits.

By default, `tide-acme` will use the Let's Encrypt staging environment, which
is suitable for testing purposes; it produces certificates signed by a staging
root so that you can verify your stack is working, but those certificates will
not be trusted in browsers or other HTTPS clients. The staging environment has
more generous rate limits for use while testing.

When you're ready to deploy to production, you can call
`.directory_lets_encrypt(true)` to switch to the production Let's Encrypt
environment, which produces certificates trusted in browsers and other HTTPS
clients. The production environment has [stricter rate
limits](https://letsencrypt.org/docs/rate-limits/).

`tide-acme` builds upon [`tide-rustls`](https://crates.io/crates/tide-rustls)
and [`rustls-acme`](https://crates.io/crates/rustls-acme).
