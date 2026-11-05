//! A push gateway for tests (W§2): `dsip-push` over HTTPS on a local port, with a self-signed certificate, pushing
//! for one FCM app (`dsip-test`) through a [`Recorder`] that delivers nothing and keeps each push. A relay built with
//! [`crate::Network::waking`] wakes through it; a device enrols at it with [`PushGateway::client`]
//! ([`dsip_transport::wake::enrol`]).
//!
//! Spec: none (infrastructure)

use std::collections::HashMap;
use std::sync::Arc;

use dsip_core::did::StaticResolver;
use dsip_core::keys::KeyPair;
use dsip_push::providers::Recorder;
use dsip_push::{Gateway, GatewayConfig, Limits, Provider};
use dsip_transport::wake::WakeClient;
use dsip_transport::waker::WakeConfig;

/// The FCM app the test gateway pushes for.
pub const APP: &str = "dsip-test";

/// A running test gateway.
pub struct PushGateway {
    /// Its DID (`did:web:localhost%3A<port>`), named in registrations.
    pub did: String,
    /// What it pushed, in order: `{class, token, data, …}` each.
    pub recorder: Recorder,
    /// A client that resolves the gateway's document and trusts its certificate.
    pub client: WakeClient,
    _dir: tempdir::Dir,
}

impl PushGateway {
    /// Start a gateway on a free local port. Call within a Tokio runtime.
    pub async fn start() -> PushGateway {
        let dir = tempdir::Dir::new("push");
        let (cert, key) = dsip_transport::tls::ensure_self_signed(&dir.0, &["localhost".into(), "127.0.0.1".into()]).expect("a certificate");
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = tcp.local_addr().expect("its address").port();
        let did = format!("did:web:localhost%3A{port}");
        let endpoint = format!("https://localhost:{port}/wake");
        let recorder = Recorder::default();
        let providers: HashMap<String, Arc<dyn Provider>> = [("fcm".to_string(), Arc::new(recorder.clone()) as Arc<dyn Provider>)].into();
        let gateway = Arc::new(Gateway::new(GatewayConfig {
            key: KeyPair::generate(),
            did: did.clone(),
            handle_key: rand_key(),
            apps: vec![("fcm".into(), APP.into())],
            providers,
            resolver: StaticResolver::default(),
            web: None,
            limits: Limits::default(),
        }));
        let mut docs = StaticResolver::default();
        docs.insert(gateway.document(&endpoint));
        let acceptor = dsip_transport::tls::acceptor(&cert, &key).expect("a TLS acceptor");
        tokio::spawn(async move { dsip_push::server::serve(gateway, &endpoint, tcp, acceptor).await });
        let client = WakeClient::new(Arc::new(docs)).with_ca(&std::fs::read(&cert).expect("the certificate")).expect("a client");
        PushGateway { did, recorder, client, _dir: dir }
    }

    /// A relay's or a mailbox's wake configuration that wakes through this gateway alone.
    pub fn waker(&self) -> WakeConfig {
        WakeConfig { client: self.client.clone(), gateways: Some(vec![self.did.clone()]), store: None }
    }
}

/// 32 random bytes: the gateway's key for its handles.
fn rand_key() -> [u8; 32] {
    KeyPair::generate().seed()
}

mod tempdir {
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// A directory removed when dropped.
    pub struct Dir(pub std::path::PathBuf);

    impl Dir {
        pub fn new(tag: &str) -> Dir {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!("dsip-testkit-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).expect("a temporary directory");
            Dir(d)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
