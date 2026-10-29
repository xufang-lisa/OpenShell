// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::session::{CaptureState, HttpSession};
use crate::l7::wait::WaitEnd;
use futures::poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DATA: &str = r#"
network_policies:
  fixture:
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: /allowed}
        deny_rules:
          - {method: GET, path: /denied}
    binaries:
      - path: /usr/bin/curl
"#;
const HEADER: &[u8] = b"GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n";

fn fixture() -> (OpaEngine, L7EvalContext) {
    let engine = OpaEngine::from_strings(POLICY_REGO, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let mut request = request_context();
    request.binary_path = "/usr/bin/curl".into();
    (engine, request)
}

#[tokio::test(start_paused = true)]
async fn production_owner_survives_reload_without_sending_or_resetting_deadline() {
    for selected in [false, true] {
        let (engine, request) = fixture();
        assert!(!engine.http_hitl_classification_enabled());
        let (mut wire, client) = tokio::io::duplex(8192);
        let (mut upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(HEADER).await.unwrap();
        let relay = relay_http_stream(client, peer, inspected_context(&engine, &request, selected));
        tokio::pin!(relay);
        assert!(poll!(relay.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        let mut bytes = Vec::new();
        upstream.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "old upstream must be dropped without HTTP writes"
        );
        tokio::time::advance(std::time::Duration::from_secs(290)).await;
        // Even coverage by an independently installed rule is NOT permission
        // to send. This slice deliberately has no release/admission path.
        engine
            .reload(
                POLICY_REGO,
                &DATA.replace("path: /allowed", "path: /missing"),
            )
            .unwrap();
        assert!(poll!(relay.as_mut()).is_pending());
        let mut response = [0; 1];
        {
            let read = wire.read(&mut response);
            tokio::pin!(read);
            assert!(poll!(read.as_mut()).is_pending());
        }
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        relay.await.unwrap();
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        assert_eq!(wire.read(&mut response).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn production_owner_terminates_on_disconnect_input_disable_quarantine_and_shutdown() {
    for mode in 0..5 {
        let (engine, request) = fixture();
        let (mut wire, client) = tokio::io::duplex(8192);
        let (mut upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(HEADER).await.unwrap();
        let relay = relay_http_stream(client, peer, inspected_context(&engine, &request, false));
        tokio::pin!(relay);
        assert!(poll!(relay.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        match mode {
            0 => wire.shutdown().await.unwrap(),
            1 => wire
                .write_all(b"GET /second HTTP/1.1\r\n\r\n")
                .await
                .unwrap(),
            2 => {
                engine.set_http_hitl_wait_enabled(false);
                engine.set_http_hitl_wait_enabled(true);
            }
            3 => {
                engine.enter_fail_closed("test quarantine").unwrap();
                engine.exit_fail_closed().unwrap();
            }
            _ => drop(engine.http_hitl_wait_runtime().shutdown_guard()),
        }
        relay.await.unwrap();
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        let mut bytes = Vec::new();
        upstream.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        wire.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "terminal wait never sends an HTTP success or final deny"
        );
    }
}

#[tokio::test]
async fn pending_owner_preserves_frozen_q_and_charge_until_transport_drop() {
    let (engine, request) = fixture();
    let (mut wire, client) = tokio::io::duplex(8192);
    let (_upstream, mut peer) = tokio::io::duplex(8192);
    let mut session = HttpSession::new(client);
    session.parts().1.enable_wait_admission();
    wire.write_all(HEADER).await.unwrap();
    assert_eq!(
        relay_http_stream_in_session(
            &mut session,
            &mut peer,
            inspected_context(&engine, &request, false)
        )
        .await
        .unwrap(),
        HttpRelayExit::PendingReview
    );
    let captured = session.slot().frozen().unwrap().captured_at();
    assert_eq!(session.slot().state(), CaptureState::PendingReview);
    assert!(
        session
            .slot()
            .classification(
                &engine
                    .generation_guard(engine.current_generation())
                    .unwrap()
            )
            .is_none()
    );
    engine.reload(POLICY_REGO, DATA).unwrap();
    assert_eq!(session.slot().frozen().unwrap().captured_header(), HEADER);
    assert_eq!(session.slot().frozen().unwrap().captured_at(), captured);
    engine.enter_fail_closed("test").unwrap();
    assert_eq!(session.wait_no_release().await, Some(WaitEnd::Quarantined));
    assert_eq!(session.slot().state(), CaptureState::Terminal);
    assert!(session.slot().frozen().is_none());
    assert!(session.parts().1.complete_exchange().is_err());
    assert_eq!(session.wait_no_release().await, None);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    drop(session);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    let mut byte = [0; 1];
    assert_eq!(wire.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn unsupported_and_explicit_denials_never_enter_waiting() {
    for header in [
        b"GET /denied HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        b"GET /missing HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n".as_slice(),
        b"POST /missing HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nx".as_slice(),
        b"GET /missing HTTP/1.0\r\nHost: example.com\r\n\r\n".as_slice(),
        &[HEADER, b"extra"].concat(),
    ] {
        let (engine, request) = fixture();
        let (mut wire, client) = tokio::io::duplex(8192);
        let (mut upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(header).await.unwrap();
        relay_http_stream(client, peer, inspected_context(&engine, &request, false))
            .await
            .unwrap();
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        let mut response = Vec::new();
        wire.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        let mut sent = Vec::new();
        upstream.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty());
    }
}

#[tokio::test]
async fn disabled_wait_retains_native_deny_even_with_observation_enabled() {
    for observe in [false, true] {
        let (engine, request) = fixture();
        engine.set_http_hitl_wait_enabled(false);
        engine.set_http_hitl_classification_enabled(observe);
        let (mut wire, client) = tokio::io::duplex(8192);
        let (_upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(HEADER).await.unwrap();
        relay_http_stream(client, peer, inspected_context(&engine, &request, false))
            .await
            .unwrap();
        let mut response = Vec::new();
        wire.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    }
}

#[tokio::test]
async fn aborting_owned_wait_drops_transport_and_returns_charge() {
    let (engine, request) = fixture();
    let (mut wire, client) = tokio::io::duplex(8192);
    let (_upstream, peer) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    {
        let relay = relay_http_stream(client, peer, inspected_context(&engine, &request, false));
        tokio::pin!(relay);
        assert!(poll!(relay.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    }
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    let mut byte = [0; 1];
    assert_eq!(wire.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn fifth_destination_waiter_is_denied_without_disturbing_four_existing_owners() {
    let (engine, request) = fixture();
    let mut owners = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..4 {
        let (mut wire, client) = tokio::io::duplex(8192);
        let (_upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(HEADER).await.unwrap();
        let mut relay = Box::pin(relay_http_stream(
            client,
            peer,
            inspected_context(&engine, &request, false),
        ));
        assert!(poll!(relay.as_mut()).is_pending());
        owners.push(relay);
        clients.push(wire);
    }
    assert_eq!(engine.http_hitl_wait_runtime().population(), 4);
    let (mut wire, client) = tokio::io::duplex(8192);
    let (_upstream, peer) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    relay_http_stream(client, peer, inspected_context(&engine, &request, false))
        .await
        .unwrap();
    let mut response = Vec::new();
    wire.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(engine.http_hitl_wait_runtime().population(), 4);
    engine.set_http_hitl_wait_enabled(false);
    for owner in owners {
        owner.await.unwrap();
    }
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    for mut client in clients {
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}

#[tokio::test]
async fn enabled_wait_does_not_hold_native_allowed_requests() {
    for selected in [false, true] {
        let (engine, request) = fixture();
        let (mut wire, client) = tokio::io::duplex(8192);
        let (mut upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(b"GET /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        relay_http_stream(client, peer, inspected_context(&engine, &request, selected))
            .await
            .unwrap();
        let mut response = Vec::new();
        wire.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
        let mut sent = Vec::new();
        upstream.read_to_end(&mut sent).await.unwrap();
        assert!(sent.starts_with(b"GET /allowed HTTP/1.1\r\n"));
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    }
}

#[tokio::test]
async fn real_tls_wait_retains_original_session_across_reload_until_quarantine() {
    use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa};
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let config = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let (wire, client) = tokio::io::duplex(64 * 1024);
        let (wire, client) = tokio::join!(
            crate::l7::tls::tls_connect_upstream(wire, "example.com", &config),
            crate::l7::tls::tls_terminate_client(client, &state, "example.com"),
        );
        let mut wire = wire.unwrap();
        let (engine, request) = fixture();
        let (mut upstream, peer) = tokio::io::duplex(8192);
        wire.write_all(HEADER).await.unwrap();
        wire.flush().await.unwrap();
        let relay = Box::pin(relay_http_stream(
            client.unwrap(),
            peer,
            inspected_context(&engine, &request, false),
        ));
        tokio::pin!(relay);
        assert!(poll!(relay.as_mut()).is_pending());
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        let mut sent = Vec::new();
        upstream.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty());
        engine.reload(POLICY_REGO, DATA).unwrap();
        assert!(poll!(relay.as_mut()).is_pending());
        let mut bytes = [0; 1024];
        {
            let read = wire.read(&mut bytes);
            tokio::pin!(read);
            assert!(poll!(read.as_mut()).is_pending());
        }
        engine.enter_fail_closed("TLS wait test").unwrap();
        relay.await.unwrap();
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        match wire.read(&mut bytes).await {
            Ok(count) => assert_eq!(count, 0),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof),
        }
    })
    .await
    .expect("TLS waiting must end on quarantine without a second handshake");
}
