//! TLS material for the `wss` requirement.
//!
//! Spec: §13.2 — the URI scheme MUST be `wss`; plaintext `ws` MUST NOT be
//! offered or accepted; TLS 1.3+ with certificate validation against the
//! advertised hostname. Impl: for local demos the relay generates a
//! self-signed certificate and clients trust it explicitly via `--ca`; no
//! plaintext fallback exists anywhere in this crate.

use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::error::{file, Error, Result};

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed certificate for `hosts` and write `cert.pem` / `key.pem` into `dir`.
/// Returns the two paths. Existing files are reused.
pub fn ensure_self_signed(dir: &Path, hosts: &[String]) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    file(dir, std::fs::create_dir_all(dir))?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    // Impl: a distinct subject per certificate. rcgen's default subject is the same everywhere
    // ("rcgen self signed cert"), and OpenSSL picks a trust anchor from a PEM bundle by subject, so a
    // bundle of several such roots verified only the first server (found on the WAN testbed).
    let key_pair = rcgen::KeyPair::generate()?;
    let tag: String = key_pair.public_key_raw().iter().rev().take(4).map(|b| format!("{b:02x}")).collect();
    let first = hosts.first().map(String::as_str).unwrap_or("localhost");
    let mut params = rcgen::CertificateParams::new(hosts.to_vec())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("DSIP self-signed {first} {tag}"));
    let cert = params.self_signed(&key_pair)?;
    file(&cert_path, std::fs::write(&cert_path, cert.pem()))?;
    file(&key_path, std::fs::write(&key_path, key_pair.serialize_pem()))?;
    Ok((cert_path, key_path))
}

/// Server-side acceptor from PEM files.
pub fn acceptor(cert_pem: &Path, key_pem: &Path) -> Result<TlsAcceptor> {
    let (certs, key) = load(cert_pem, key_pem)?;
    let cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

fn load(cert_pem: &Path, key_pem: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    install_provider();
    let certs: Vec<CertificateDer<'static>> =
        file(cert_pem, rustls_pemfile::certs(&mut std::io::BufReader::new(file(cert_pem, std::fs::File::open(cert_pem))?)).collect())?;
    let key: PrivateKeyDer<'static> =
        file(key_pem, rustls_pemfile::private_key(&mut std::io::BufReader::new(file(key_pem, std::fs::File::open(key_pem))?)))?
            .ok_or_else(|| Error::NoPrivateKey(key_pem.to_path_buf()))?;
    Ok((certs, key))
}

/// A service's certificate, read again from its files on [`Certificates::reload`]: a renewed certificate is served
/// from the next TLS handshake on, and the connections already open (bound devices) are untouched.
///
/// Impl (service-nodes plan S5): a renewal tool (the Let's Encrypt deploy hook) sends `SIGHUP`
/// ([`Certificates::reload_on_sighup`]) instead of restarting the service. A reload that fails (a half-written file,
/// a key that does not match) keeps the certificate being served, and says why.
#[derive(Debug)]
pub struct Certificates {
    cert_pem: std::path::PathBuf,
    key_pem: std::path::PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
}

impl Certificates {
    /// Read the certificate chain and private key (PEM).
    pub fn load(cert_pem: &Path, key_pem: &Path) -> Result<Arc<Certificates>> {
        let current = RwLock::new(certified(cert_pem, key_pem)?);
        Ok(Arc::new(Certificates { cert_pem: cert_pem.to_path_buf(), key_pem: key_pem.to_path_buf(), current }))
    }

    /// Read the files again; on success the new certificate is served from the next handshake, on failure the
    /// current one stays.
    pub fn reload(&self) -> Result<()> {
        let next = certified(&self.cert_pem, &self.key_pem)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    /// An acceptor serving whichever certificate is current at each handshake.
    pub fn acceptor(self: &Arc<Self>) -> TlsAcceptor {
        let cfg = ServerConfig::builder().with_no_client_auth().with_cert_resolver(self.clone());
        TlsAcceptor::from(Arc::new(cfg))
    }

    /// [`Certificates::reload`] on every `SIGHUP`, logging the outcome, until the process ends.
    #[cfg(unix)]
    pub fn reload_on_sighup(self: &Arc<Self>) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let certs = self.clone();
        Ok(tokio::spawn(async move {
            while hup.recv().await.is_some() {
                match certs.reload() {
                    Ok(()) => tracing::info!("SIGHUP: certificate reloaded from {}", certs.cert_pem.display()),
                    Err(e) => tracing::warn!("SIGHUP: certificate not reloaded, still serving the previous one: {e}"),
                }
            }
        }))
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().unwrap_or_else(|e| e.into_inner()).clone())
    }
}

fn certified(cert_pem: &Path, key_pem: &Path) -> Result<Arc<CertifiedKey>> {
    let (certs, key) = load(cert_pem, key_pem)?;
    if certs.is_empty() {
        return Err(rustls::Error::General(format!("no certificate in {}", cert_pem.display())).into());
    }
    let provider = rustls::crypto::ring::default_provider();
    let ck = CertifiedKey::from_der(certs, key, &provider)?;
    Ok(Arc::new(ck))
}

/// Client config trusting the platform's roots, and beside them the CA/self-signed certificate(s) in `ca_pem`: a
/// service dials peers under self-signed certificates (a lab) and under public ones (a deployment) from the same
/// configuration. Where the platform has no root store this process can read (Android, whose store
/// `rustls-native-certs` does not reach), the roots are webpki-roots' copy of Mozilla's. Always `Some`; the `Option`
/// is kept for callers written when `None` meant tokio-tungstenite's default connector, which on Android fails every
/// `wss` connection with "no native root CA certificates found".
pub fn client_config(ca_pem: Option<&Path>) -> Result<Option<Arc<ClientConfig>>> {
    install_provider();
    let mut roots = platform_roots(rustls_native_certs::load_native_certs().certs);
    if let Some(p) = ca_pem {
        for c in rustls_pemfile::certs(&mut std::io::BufReader::new(file(p, std::fs::File::open(p))?)) {
            roots.add(file(p, c)?)?;
        }
    }
    let cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Some(Arc::new(cfg)))
}

/// The roots of the platform's store, `native`; webpki-roots' when it gives none that parse.
fn platform_roots(native: Vec<CertificateDer<'static>>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(native);
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_platform_store_the_roots_are_mozillas() {
        // Android: rustls-native-certs finds no store
        assert_eq!(platform_roots(vec![]).len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(client_config(None).unwrap().is_some());
    }

    #[test]
    fn a_reload_serves_the_new_certificate_and_a_bad_one_keeps_the_old() {
        let dir = std::env::temp_dir().join(format!("dsip-tls-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (cert, key) = ensure_self_signed(&dir.join("a"), &["localhost".into()]).unwrap();
        let certs = Certificates::load(&cert, &key).unwrap();
        let first = certs.current.read().unwrap().cert[0].clone();
        // renewed: a new pair written over the files
        let (c2, k2) = ensure_self_signed(&dir.join("b"), &["localhost".into()]).unwrap();
        std::fs::copy(&c2, &cert).unwrap();
        std::fs::copy(&k2, &key).unwrap();
        certs.reload().unwrap();
        let second = certs.current.read().unwrap().cert[0].clone();
        assert_ne!(first, second);
        // half-written: the certificate kept
        std::fs::write(&cert, "").unwrap();
        assert!(certs.reload().is_err());
        // a key that is not the certificate's: kept too
        std::fs::copy(&c2, &cert).unwrap();
        std::fs::write(&key, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap();
        assert!(certs.reload().is_err());
        assert_eq!(certs.current.read().unwrap().cert[0], second);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
