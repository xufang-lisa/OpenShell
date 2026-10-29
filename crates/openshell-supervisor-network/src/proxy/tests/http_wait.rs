// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::poll;

#[tokio::test]
async fn explicit_and_virtual_connect_production_ingress_wait_without_http_writes() {
    let Some(ip) = non_loopback_test_ipv4() else {
        eprintln!("skipping CONNECT wait fixture: no routable local test address");
        return;
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for virtual_connect in [false, true] {
            let listener = TcpListener::bind((ip, 0)).await.unwrap();
            let destination = listener.local_addr().unwrap();
            let data = policy_with_native_executable_paths(&format!(
                r#"
network_policies:
  fixture:
    endpoints:
      - host: "{ip}"
        port: {port}
        protocol: rest
        enforcement: enforce
        allowed_ips: ["{ip}/32"]
        rules:
          - allow: {{method: GET, path: /allowed}}
    binaries:
      - path: /usr/bin/curl
"#,
                port = destination.port()
            ));
            let engine = Arc::new(
                native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                    .unwrap(),
            );
            engine.set_http_hitl_wait_enabled(true);
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
            let header = format!("GET /missing HTTP/1.1\r\nHost: {destination}\r\n\r\n");
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
                None,
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
            let mut sent = Vec::new();
            upstream.read_to_end(&mut sent).await.unwrap();
            assert!(sent.is_empty());
            if !virtual_connect {
                let mut response = [0; 1024];
                let count = wire.read(&mut response).await.unwrap();
                assert!(response[..count].starts_with(b"HTTP/1.1 200 Connection Established"));
            }
            engine
                .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap();
            assert!(poll!(handler.as_mut()).is_pending());
            assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
            engine.enter_fail_closed("CONNECT wait test").unwrap();
            handler.await.unwrap();
            assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
            let mut response = Vec::new();
            wire.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
        }
    })
    .await
    .expect("explicit/virtual CONNECT no-release wait must terminate");
}

#[tokio::test]
async fn forward_production_ingress_keeps_reader_across_reload_without_dialing() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let data = policy_with_native_executable_paths(&format!(
            r#"
network_policies:
  fixture:
    endpoints:
      - host: "127.0.0.1"
        port: {port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {{method: GET, path: /allowed}}
    binaries:
      - path: /usr/bin/curl
"#,
            port = destination.port()
        ));
        let engine = Arc::new(
            native_identity_engine(include_str!("../../../data/sandbox-policy.rego"), &data)
                .unwrap(),
        );
        engine.set_http_hitl_wait_enabled(true);
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
            "GET http://{destination}/a/../missing HTTP/1.1\r\nHost: {destination}\r\n\r\n"
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
            None,
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
        engine
            .reload(include_str!("../../../data/sandbox-policy.rego"), &data)
            .unwrap();
        assert!(poll!(handler.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        {
            let accept = upstream.accept();
            tokio::pin!(accept);
            assert!(
                poll!(accept.as_mut()).is_pending(),
                "FORWARD must not dial upstream while waiting"
            );
        }
        engine.enter_fail_closed("FORWARD wait quarantine").unwrap();
        handler.await.unwrap();
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        let mut response = Vec::new();
        wire.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    })
    .await
    .expect("production FORWARD waiter must terminate on quarantine");
}
