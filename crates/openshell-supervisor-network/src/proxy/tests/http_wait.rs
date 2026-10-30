// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::poll;

#[derive(Default)]
struct HeldIntentRecorder {
    metadata: std::sync::Mutex<Vec<String>>,
    decision: AtomicU32,
    observations: AtomicU32,
}

impl crate::l7::proposal::HeldProposalService for HeldIntentRecorder {
    fn observe<'a>(
        &'a self,
        workspace: &'a str,
        chunk_id: &'a str,
    ) -> crate::l7::proposal::ProposalObservation<'a> {
        Box::pin(async move {
            assert_eq!(workspace, "fixture-team");
            assert_eq!(chunk_id, "durable-fixture-chunk");
            let decision = match self.decision.load(Ordering::Acquire) {
                0 => crate::l7::proposal::ReviewDecision::Pending,
                1 => crate::l7::proposal::ReviewDecision::Approved,
                2 => crate::l7::proposal::ReviewDecision::Rejected,
                _ => unreachable!(),
            };
            self.observations.fetch_add(1, Ordering::Release);
            Ok(decision)
        })
    }

    fn submit<'a>(
        &'a self,
        input: &'a crate::l7::proposal::HeldProposalInput,
    ) -> crate::l7::proposal::ProposalSubmission<'a> {
        Box::pin(async move {
            assert_eq!(input.method(), "GET");
            assert_eq!(input.path(), "/missing");
            assert_eq!(input.workspace(), "fixture-team");
            assert_eq!(input.scope().endpoints.len(), 1);
            assert!(input.scope().endpoints[0].rules.is_empty());
            let metadata = input.review_metadata();
            for secret in ["query-sentinel", "header-sentinel", "cookie-sentinel"] {
                assert!(!metadata.contains(secret));
            }
            self.metadata.lock().unwrap().push(metadata);
            Ok("durable-fixture-chunk".into())
        })
    }
}

const HELD_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nheld-response!";

async fn assert_no_held_dial(listener: &TcpListener) {
    let accept = listener.accept();
    tokio::pin!(accept);
    assert!(
        poll!(accept.as_mut()).is_pending(),
        "unexpected upstream connection"
    );
}

async fn drive_held_until<F: Future>(mut handler: std::pin::Pin<&mut F>, ready: impl Fn() -> bool) {
    while !ready() {
        assert!(
            poll!(handler.as_mut()).is_pending(),
            "handler exited while held"
        );
        tokio::task::yield_now().await;
    }
}

async fn read_held_close<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, tls: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    match stream.read_to_end(&mut bytes).await {
        Ok(_) => {}
        // Production drops retired TLS streams without close_notify. This is
        // transport EOF, not proof of a clean TLS shutdown.
        Err(error)
            if tls
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
        Err(error) => panic!("reading held transport: {error}"),
    }
    bytes
}

async fn serve_held_once<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    destination: SocketAddr,
    tls: bool,
) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
        assert!(header.len() < 8192);
    }
    let header = String::from_utf8(header).unwrap();
    assert_eq!(
        header.lines().next(),
        Some("GET /missing?secret=query-sentinel HTTP/1.1")
    );
    assert!(header.contains(&format!("Host: {destination}\r\n")));
    for sentinel in ["query-sentinel", "header-sentinel", "cookie-sentinel"] {
        assert_eq!(header.matches(sentinel).count(), 1);
    }
    assert!(header.contains("Authorization: header-sentinel\r\n"));
    assert!(header.contains("Cookie: cookie-sentinel\r\n"));
    stream.write_all(HELD_RESPONSE).await.unwrap();
    stream.flush().await.unwrap();
    // Keep the upstream alive until the one-shot relay drops it. Any replay
    // or second request on this same connection becomes an assertion failure.
    assert!(read_held_close(stream, tls).await.is_empty());
}

fn held_proposal_context() -> Arc<PolicyLocalContext> {
    Arc::new(PolicyLocalContext::new(
        None,
        None,
        None,
        AgentProposals::default(),
        tokio::sync::watch::channel("fixture-team".to_string()).1,
    ))
}

#[tokio::test]
async fn explicit_and_virtual_connect_production_ingress_resume_once() {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping CONNECT wait fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for virtual_connect in [false, true] {
            let listener = TcpListener::bind((ip, 0)).await.unwrap();
            let destination = listener.local_addr().unwrap();
            let data = policy_with_native_executable_paths(&format!(
                "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
                port = destination.port()
            ));
            let engine = Arc::new(
                native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                    .unwrap(),
            );
            engine.set_http_hitl_wait_enabled(true);
            engine.attach_http_hitl_policy_observer();
            let recorder = Arc::new(HeldIntentRecorder::default());
            engine.set_http_hitl_proposal_service(recorder.clone());
            let cache = Arc::new(BinaryIdentityCache::new());
            let identity = ContractBinaryIdentity {
                executable: ContractExecutableIdentity {
                    path: executable_path("/usr/bin/curl"),
                    digest: Some("44".repeat(32).parse().unwrap()),
                },
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            };
            let (client, mut wire) = tokio::io::duplex(8192);
            let (stream, supplied_identity, socket_addrs, transparent) = if virtual_connect {
                let (decision, completion) = tokio::sync::oneshot::channel();
                let pending = PendingTcpOpen {
                    stream: Box::new(client),
                    binary_identity: Ok(identity),
                    destination,
                    socket: Some(
                        openshell_isolation_interface::contract::NetworkSocketMetadata {
                            socket_cookie: 7,
                            nonblocking: false,
                            process_generation: 1,
                        },
                    ),
                    policy_generation: engine.current_generation(),
                    timing: MediationTiming::default(),
                    decision,
                };
                let admitted = preauthorize_transparent_open(
                    pending, None, &engine, &cache, None, None, false, None,
                )
                .await
                .unwrap();
                assert_eq!(completion.await.unwrap(), TcpOpenDecision::RelayReady);
                admitted
            } else {
                let stream: BoundaryDuplexStream = Box::new(client);
                (stream, Some(Ok(identity)), None, None)
            };
            let ca = crate::l7::tls::SandboxCa::generate().unwrap();
            let config = Arc::new(
                openshell_crypto::tls::client_builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            );
            let tls = Arc::new(ProxyTlsState::new(
                crate::l7::tls::CertCache::new(ca),
                config,
            ));
            let header = format!("GET /missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n");
            let request = if virtual_connect {
                header
            } else {
                format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n{header}")
            };
            wire.write_all(request.as_bytes()).await.unwrap();
            let handler = Box::pin(handle_mediated_connection(
                tokio::io::BufReader::new(stream),
                supplied_identity,
                socket_addrs,
                transparent,
                None,
                engine.clone(),
                cache,
                Arc::new(AtomicU32::new(0)),
                Some(tls),
                Some(held_proposal_context()),
                AgentProposals::default(),
                Arc::new(None),
                Arc::new(None),
                Arc::new(None),
                None,
                None,
                None,
                None,
                None,
                None,
            ));
            tokio::pin!(handler);
            assert!(poll!(handler.as_mut()).is_pending());
            // The handler must continue polling DNS/connect while the test
            // awaits accept; merely polling it once can strand that future.
            let (mut upstream, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                result = handler.as_mut() => panic!("CONNECT exited before upstream accept: {result:?}"),
            };
            while engine.http_hitl_wait_runtime().population() == 0 {
                assert!(poll!(handler.as_mut()).is_pending());
                tokio::task::yield_now().await;
            }
            let sent = tokio::select! {
                sent = read_held_close(&mut upstream, false) => sent,
                result = handler.as_mut() => panic!("CONNECT exited while Pending: {result:?}"),
            };
            assert!(sent.is_empty());
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
            if !virtual_connect {
                let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                let mut response = vec![0; expected.len()];
                tokio::select! {
                    result = wire.read_exact(&mut response) => { result.unwrap(); },
                    result = handler.as_mut() => panic!("CONNECT exited before envelope response: {result:?}"),
                }
                assert_eq!(response, expected);
            }
            engine
                .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap();
            let observations = recorder.observations.load(Ordering::Acquire);
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            recorder.decision.store(1, Ordering::Release);
            let observations = recorder.observations.load(Ordering::Acquire);
            engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap();
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            engine
                .reload(
                    include_str!("../../../data/sandbox-policy.rego"),
                    &data.replace("path: /allowed", "path: /missing"),
                )
                .unwrap();
            let server = async {
                let (mut fresh, _) = listener.accept().await.unwrap();
                serve_held_once(&mut fresh, destination, false).await;
            };
            let client = async {
                assert_eq!(read_held_close(&mut wire, false).await, HELD_RESPONSE);
            };
            let (result, (), ()) = tokio::join!(handler, server, client);
            result.unwrap();
            assert_no_held_dial(&listener).await;
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
            assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        }
    })
    .await
    .expect("explicit/virtual CONNECT must resume exactly once and close");
}

#[tokio::test]
async fn forward_production_ingress_resume_once_without_early_dial() {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping FORWARD resume fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let upstream = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let data = policy_with_native_executable_paths(&format!(
            "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
            port = destination.port()
        ));
        let engine = Arc::new(
            native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap(),
        );
        engine.set_http_hitl_wait_enabled(true);
        engine.attach_http_hitl_policy_observer();
        let recorder = Arc::new(HeldIntentRecorder::default());
        engine.set_http_hitl_proposal_service(recorder.clone());
        let identity = ContractBinaryIdentity {
            executable: ContractExecutableIdentity {
                path: executable_path("/usr/bin/curl"),
                digest: Some("44".repeat(32).parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let (client, mut wire) = tokio::io::duplex(8192);
        let request = format!(
            "GET http://{destination}/a/../missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n"
        );
        let handler = Box::pin(handle_mediated_connection(
            tokio::io::BufReader::new(Box::new(client)),
            Some(Ok(identity)),
            None,
            None,
            None,
            engine.clone(),
            Arc::new(BinaryIdentityCache::new()),
            Arc::new(AtomicU32::new(0)),
            None,
            Some(held_proposal_context()),
            AgentProposals::default(),
            Arc::new(None),
            Arc::new(None),
            Arc::new(None),
            None,
            None,
            None,
            None,
            None,
            None,
        ));
        tokio::pin!(handler);
        // Exercise the real initial capture boundary, not the test-only
        // FORWARD wrapper that creates its slot after capture.
        let boundary = request.len() / 2;
        wire.write_all(&request.as_bytes()[..boundary])
            .await
            .unwrap();
        assert!(poll!(handler.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        wire.write_all(&request.as_bytes()[boundary..])
            .await
            .unwrap();
        assert!(poll!(handler.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        assert_no_held_dial(&upstream).await;
        engine
            .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
            .unwrap();
        let observations = recorder.observations.load(Ordering::Acquire);
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&upstream).await;
        // Coverage alone is not approval. Observe the installed rule while
        // the deterministic reviewer still reports Pending.
        engine
            .reload(
                include_str!("../../../data/sandbox-policy.rego"),
                &data.replace("path: /allowed", "path: /missing"),
            )
            .unwrap();
        let observations = recorder.observations.load(Ordering::Acquire);
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&upstream).await;
        recorder.decision.store(1, Ordering::Release);
        // Wake observation without relying on wall-clock polling latency.
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data.replace("path: /allowed", "path: /missing")).unwrap();
        let server = async {
            let (mut fresh, _) = upstream.accept().await.unwrap();
            serve_held_once(&mut fresh, destination, false).await;
        };
        let client = async {
            assert_eq!(read_held_close(&mut wire, false).await, HELD_RESPONSE);
        };
        let (result, (), ()) = tokio::join!(handler, server, client);
        result.unwrap();
        assert_no_held_dial(&upstream).await;
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    })
    .await
    .expect("production FORWARD must resume once only after approval and coverage");
}

fn held_test_identity() -> ContractBinaryIdentity {
    // Supplied by this trusted test fixture, NOT sampled from a live process.
    ContractBinaryIdentity {
        executable: ContractExecutableIdentity {
            path: executable_path("/usr/bin/curl"),
            digest: Some("44".repeat(32).parse().unwrap()),
        },
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    }
}

fn held_test_engine(destination: SocketAddr) -> (Arc<OpaEngine>, Arc<HeldIntentRecorder>, String) {
    let ip = destination.ip();
    let data = policy_with_native_executable_paths(&format!(
        "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {port}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
        port = destination.port(),
    ));
    let engine = Arc::new(
        native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap(),
    );
    engine.attach_http_hitl_policy_observer();
    let recorder = Arc::new(HeldIntentRecorder::default());
    engine.set_http_hitl_proposal_service(recorder.clone());
    (engine, recorder, data)
}

async fn held_test_handler(
    client: tokio::io::DuplexStream,
    engine: Arc<OpaEngine>,
    tls: Option<Arc<ProxyTlsState>>,
) -> Result<()> {
    Box::pin(handle_mediated_connection(
        tokio::io::BufReader::new(Box::new(client)),
        Some(Ok(held_test_identity())),
        None,
        None,
        None,
        engine,
        Arc::new(BinaryIdentityCache::new()),
        Arc::new(AtomicU32::new(0)),
        tls,
        Some(held_proposal_context()),
        AgentProposals::default(),
        Arc::new(None),
        Arc::new(None),
        Arc::new(None),
        None,
        None,
        None,
        None,
        None,
        None,
    ))
    .await
}

#[derive(Clone, Copy, Debug)]
enum HeldForwardEnd {
    Rejected,
    Disabled,
    DefaultOff,
    ClientClosed,
}

async fn held_forward_terminal_case(end: HeldForwardEnd) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping FORWARD terminal fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), Box::pin(async {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let (engine, recorder, data) = held_test_engine(destination);
        if !matches!(end, HeldForwardEnd::DefaultOff) {
            engine.set_http_hitl_wait_enabled(true);
        }
        let (client, mut wire) = tokio::io::duplex(8192);
        wire.write_all(format!(
            "GET http://{destination}/missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n"
        ).as_bytes()).await.unwrap();
        let handler = held_test_handler(client, engine.clone(), None);
        tokio::pin!(handler);
        if !matches!(end, HeldForwardEnd::DefaultOff) {
            drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > 0).await;
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            assert_no_held_dial(&listener).await;
            match end {
                HeldForwardEnd::Rejected => recorder.decision.store(2, Ordering::Release),
                HeldForwardEnd::Disabled => {
                    recorder.decision.store(1, Ordering::Release);
                    engine.set_http_hitl_wait_enabled(false);
                }
                HeldForwardEnd::ClientClosed => {
                    recorder.decision.store(1, Ordering::Release);
                    wire.shutdown().await.unwrap();
                }
                HeldForwardEnd::DefaultOff => unreachable!(),
            }
            // Even installed coverage must not revive rejection, cancellation
            // or a disabled wait epoch.
            engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data.replace("path: /allowed", "path: /missing")).unwrap();
        }
        let client = async { read_held_close(&mut wire, false).await };
        let (result, response) = tokio::join!(handler, client);
        result.unwrap();
        assert_no_held_dial(&listener).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        if matches!(end, HeldForwardEnd::DefaultOff) {
            assert!(response.starts_with(b"HTTP/1.1 403"));
            assert!(recorder.metadata.lock().unwrap().is_empty());
            assert_eq!(recorder.observations.load(Ordering::Acquire), 0);
        } else {
            assert!(response.is_empty(), "terminal hold must not produce an upstream response");
            assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
        }
    })).await.unwrap_or_else(|_| panic!("FORWARD terminal case timed out: {end:?}"));
}

#[tokio::test]
async fn forward_production_ingress_rejected_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::Rejected).await;
}

#[tokio::test]
async fn forward_production_ingress_disabled_epoch_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::Disabled).await;
}

#[tokio::test]
async fn forward_production_ingress_default_off_denies_without_waiting() {
    held_forward_terminal_case(HeldForwardEnd::DefaultOff).await;
}

#[tokio::test]
async fn forward_production_ingress_client_closed_before_approval_never_dials() {
    held_forward_terminal_case(HeldForwardEnd::ClientClosed).await;
}

#[derive(Clone, Copy, Debug)]
enum HeldTlsEnd {
    Response,
    StaleBeforeWrite,
    ClientClosedBeforeWrite,
}

async fn held_tls_ingress_case(
    original_version: &'static rustls::SupportedProtocolVersion,
    upstream_version: &'static rustls::SupportedProtocolVersion,
    end: HeldTlsEnd,
) {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping CONNECT TLS fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), Box::pin(async {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let (engine, recorder, data) = held_test_engine(destination);
        engine.set_http_hitl_wait_enabled(true);
        let ca = crate::l7::tls::SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let original_config = openshell_crypto::tls::client_builder_with_protocol_versions(&[original_version])
            .with_root_certificates(roots.clone()).with_no_client_auth();
        let upstream_config = openshell_crypto::tls::client_builder_with_protocol_versions(&[upstream_version])
            .with_root_certificates(roots).with_no_client_auth();
        // Both real TLS peers use this same fixture CA/ProxyTlsState. There is
        // no certificate-verification bypass or pre-created plaintext pair.
        let state = Arc::new(ProxyTlsState::new(crate::l7::tls::CertCache::new(ca), Arc::new(upstream_config)));
        let (client, mut wire) = tokio::io::duplex(64 * 1024);
        wire.write_all(format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes()).await.unwrap();
        let handler = held_test_handler(client, engine.clone(), Some(state.clone()));
        tokio::pin!(handler);
        let (old, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            result = handler.as_mut() => panic!("TLS ingress exited before old accept: {result:?}"),
        };
        let connect_response = async {
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(wire.read_u8().await.unwrap());
                assert!(response.len() < 1024);
            }
            assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        };
        tokio::select! {
            () = connect_response => {},
            result = handler.as_mut() => panic!("TLS ingress exited before CONNECT response: {result:?}"),
        }
        let hostname = ip.to_string();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(original_config));
        let handshakes = async {
            tokio::join!(
                connector.connect(rustls::pki_types::ServerName::try_from(hostname.clone()).unwrap(), wire),
                crate::l7::tls::tls_terminate_client(old, &state, &hostname),
            )
        };
        let (wire, old) = tokio::select! {
            pair = handshakes => pair,
            result = handler.as_mut() => panic!("TLS ingress exited during handshakes: {result:?}"),
        };
        let mut wire = wire.unwrap();
        let mut old = old.unwrap();
        assert_eq!(wire.get_ref().1.protocol_version(), Some(original_version.version));
        wire.write_all(format!("GET /a/../missing?secret=query-sentinel HTTP/1.1\r\nHost: {destination}\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n").as_bytes()).await.unwrap();
        wire.flush().await.unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > 0).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        let retired = tokio::select! {
            bytes = read_held_close(&mut old, true) => bytes,
            result = handler.as_mut() => panic!("TLS ingress exited while Pending: {result:?}"),
        };
        assert!(retired.is_empty(), "retired upstream must see zero HTTP bytes");
        assert_no_held_dial(&listener).await;
        let observations = recorder.observations.load(Ordering::Acquire);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &data).unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_no_held_dial(&listener).await;
        let covered = data.replace("path: /allowed", "path: /missing");
        let observations = recorder.observations.load(Ordering::Acquire);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
        drive_held_until(handler.as_mut(), || recorder.observations.load(Ordering::Acquire) > observations).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_no_held_dial(&listener).await;
        recorder.decision.store(1, Ordering::Release);
        engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
        let (fresh, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            result = handler.as_mut() => panic!("TLS ingress exited before fresh accept: {result:?}"),
        };
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        match end {
            HeldTlsEnd::Response => {
                let server = async {
                    let mut fresh = crate::l7::tls::tls_terminate_client(fresh, &state, &hostname).await.unwrap();
                    serve_held_once(&mut fresh, destination, true).await;
                };
                let client = async {
                    // This is the ORIGINAL TLS client object: no replacement
                    // handshake after either unrelated or covering reload.
                    assert_eq!(read_held_close(&mut wire, true).await, HELD_RESPONSE);
                    assert_eq!(wire.get_ref().1.protocol_version(), Some(original_version.version));
                };
                let (result, (), ()) = tokio::join!(handler, server, client);
                result.unwrap();
            }
            HeldTlsEnd::StaleBeforeWrite | HeldTlsEnd::ClientClosedBeforeWrite => {
                // Deliberately do not poll the fresh server handshake yet.
                // Readmission is blocked in TLS establishment, before any
                // application write. Cancel or stale its generation there.
                assert!(poll!(handler.as_mut()).is_pending());
                if matches!(end, HeldTlsEnd::StaleBeforeWrite) {
                    engine.reload(include_str!("../../../data/sandbox-policy.rego"), &covered).unwrap();
                } else {
                    wire.shutdown().await.unwrap();
                }
                let server = async {
                    assert!(crate::l7::tls::tls_terminate_client(fresh, &state, &hostname).await.is_err(),
                        "prewrite cancellation must abort fresh TLS, not send HTTP");
                };
                let client = async {
                    assert!(read_held_close(&mut wire, true).await.is_empty());
                };
                let (result, (), ()) = tokio::join!(handler, server, client);
                result.unwrap();
            }
        }
        assert_no_held_dial(&listener).await;
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        assert_eq!(recorder.metadata.lock().unwrap().len(), 1);
    })).await.unwrap_or_else(|_| panic!("TLS ingress timed out: {end:?}, original={:?}, upstream={:?}", original_version.version, upstream_version.version));
}

#[tokio::test]
async fn connect_production_ingress_original_tls_survives_reload_fresh_upstream_tls_four_grid() {
    for original in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for upstream in [&rustls::version::TLS12, &rustls::version::TLS13] {
            held_tls_ingress_case(original, upstream, HeldTlsEnd::Response).await;
        }
    }
}

#[tokio::test]
async fn connect_production_ingress_stale_before_fresh_tls_write_aborts() {
    held_tls_ingress_case(
        &rustls::version::TLS13,
        &rustls::version::TLS13,
        HeldTlsEnd::StaleBeforeWrite,
    )
    .await;
}

#[tokio::test]
async fn connect_production_ingress_client_cancel_before_fresh_tls_write_aborts() {
    held_tls_ingress_case(
        &rustls::version::TLS13,
        &rustls::version::TLS13,
        HeldTlsEnd::ClientClosedBeforeWrite,
    )
    .await;
}
