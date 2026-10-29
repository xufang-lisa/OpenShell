// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::hitl::evaluate_http_l7_request_with_slot;
use crate::l7::relay::L7EvalContext;
use crate::l7::rest::RestProvider;
use crate::l7::{L7EndpointConfig, L7RequestInfo};
use crate::opa::OpaEngine;
use futures::poll;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");
const DATA: &str = r#"
network_policies:
  fixture:
    endpoints:
      - host: api.example.test
        port: 80
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: /allowed}
    binaries:
      - path: /usr/bin/curl
"#;
const HEADER: &[u8] = b"GET /missing HTTP/1.1\r\nHost: api.example.test\r\n\r\n";

fn engine() -> OpaEngine {
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_classification_enabled(true);
    engine
}

fn context() -> L7EvalContext {
    L7EvalContext {
        host: "api.example.test".into(),
        port: 80,
        request_default_port: Some(80),
        policy_name: "fixture".into(),
        binary_path: "/usr/bin/curl".into(),
        ..Default::default()
    }
}

fn config() -> L7EndpointConfig {
    crate::l7::parse_l7_config(
        &serde_json::from_value(serde_json::json!({"protocol":"rest","enforcement":"enforce"}))
            .unwrap(),
    )
    .unwrap()
}

fn info(request: &L7Request) -> L7RequestInfo {
    L7RequestInfo {
        action: request.action.clone(),
        target: request.target.clone(),
        query_params: request.query_params.clone(),
        graphql: None,
        jsonrpc: None,
    }
}

#[tokio::test]
async fn cancellation_mid_header_keeps_prefix_and_native_canonicalization() {
    let (mut wire, client) = tokio::io::duplex(8192);
    let mut session = HttpSession::new(client);
    let provider = RestProvider::default();
    let prefix = b"GET /a/../missing?mode=safe HTTP/1.1\r\nHost: api.example.test\r";
    wire.write_all(prefix).await.unwrap();
    {
        let (reader, slot) = session.parts();
        let capture = provider.capture_request(reader, slot);
        tokio::pin!(capture);
        assert!(poll!(capture.as_mut()).is_pending());
    }
    assert_eq!(session.slot().state(), CaptureState::Capturing);
    assert_eq!(session.slot().partial_header(), prefix);
    assert!(session.slot().frozen().is_none());

    wire.write_all(b"\n\r\n").await.unwrap();
    let (reader, slot) = session.parts();
    let request = provider
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.target, "/missing");
    assert_eq!(request.query_params["mode"], ["safe"]);
    let frozen = slot.frozen().unwrap();
    assert!(frozen.captured_header().starts_with(b"GET /a/../missing?"));
    assert!(frozen.request().raw_header.starts_with(b"GET /missing?"));
    assert_eq!(slot.state(), CaptureState::Frozen);
}

#[tokio::test]
async fn cancellation_at_every_incomplete_header_boundary_preserves_all_bytes() {
    for boundary in 0..HEADER.len() {
        let (mut wire, client) = tokio::io::duplex(8192);
        let mut session = HttpSession::new(client);
        let provider = RestProvider::default();
        wire.write_all(&HEADER[..boundary]).await.unwrap();
        {
            let (reader, slot) = session.parts();
            let capture = provider.capture_request(reader, slot);
            tokio::pin!(capture);
            assert!(poll!(capture.as_mut()).is_pending());
        }
        assert_eq!(session.slot().partial_header(), &HEADER[..boundary]);
        assert!(session.slot().frozen().is_none());
        wire.write_all(&HEADER[boundary..]).await.unwrap();
        let (reader, slot) = session.parts();
        let request = provider
            .capture_request(reader, slot)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.raw_header, HEADER);
        assert_eq!(slot.frozen().unwrap().captured_header(), HEADER);
        assert!(reader.buffer().is_empty());
    }
}

#[tokio::test]
async fn truncated_or_invalid_headers_never_become_frozen_or_classified() {
    for header in [
        b"GET /missing HTTP/1.1\r\nHost: api.example.test\r".as_slice(),
        b"GET /missing HTTP/1.1\r\nBad Header: rejected\r\n\r\n".as_slice(),
    ] {
        let (mut wire, client) = tokio::io::duplex(8192);
        wire.write_all(header).await.unwrap();
        wire.shutdown().await.unwrap();
        let mut session = HttpSession::new(client);
        let (reader, slot) = session.parts();
        assert!(
            RestProvider::default()
                .capture_request(reader, slot)
                .await
                .is_err()
        );
        assert_eq!(slot.state(), CaptureState::Capturing);
        assert_eq!(slot.partial_header(), header);
        assert!(slot.frozen().is_none());
        slot.terminate();
        assert_eq!(slot.state(), CaptureState::Terminal);
        assert!(slot.partial_header().is_empty());
    }
}

#[tokio::test]
async fn freeze_then_cancel_before_classification_keeps_exact_request() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let (frozen_tx, mut frozen_rx) = tokio::sync::oneshot::channel();
    {
        let (reader, slot) = session.parts();
        let borrowed = async {
            RestProvider::default()
                .capture_request(reader, slot)
                .await
                .unwrap();
            frozen_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        };
        tokio::pin!(borrowed);
        tokio::select! {
            biased;
            () = &mut borrowed => panic!("barrier must block classification"),
            result = &mut frozen_rx => result.unwrap(),
        }
    }
    let captured_at = session.slot().frozen().unwrap().captured_at();
    assert_eq!(session.slot().state(), CaptureState::Frozen);
    let engine = engine();
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    assert!(session.slot().classification(&guard).is_none());
    let (reader, slot) = session.parts();
    let request = RestProvider::default()
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.raw_header, HEADER);
    assert_eq!(slot.frozen().unwrap().captured_at(), captured_at);
    reader.write_all(b"still-the-same-client").await.unwrap();
    let mut reply = [0; 21];
    wire.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"still-the-same-client");
}

#[tokio::test]
async fn reload_invalidates_observation_not_frozen_request_or_capture_time() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let engine = engine();
    let old = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    let (reader, slot) = session.parts();
    let request = RestProvider::default()
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    let captured_at = slot.frozen().unwrap().captured_at();
    let native = evaluate_http_l7_request_with_slot(
        &old,
        &context(),
        &config(),
        &request,
        &info(&request),
        slot,
    )
    .unwrap();
    assert!(!native.0);
    assert_eq!(
        slot.classification(old.generation_guard())
            .unwrap()
            .eligibility,
        RestHitlEligibility::EligibleForReview
    );

    engine.reload(POLICY, DATA).unwrap();
    assert!(slot.classification(old.generation_guard()).is_none());
    let fresh = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    assert!(slot.classification(fresh.generation_guard()).is_none());
    slot.invalidate_classification();
    assert_eq!(slot.state(), CaptureState::Frozen);
    assert_eq!(slot.frozen().unwrap().request().raw_header, HEADER);
    assert_eq!(slot.frozen().unwrap().captured_at(), captured_at);
    evaluate_http_l7_request_with_slot(
        &fresh,
        &context(),
        &config(),
        &request,
        &info(&request),
        slot,
    )
    .unwrap();
    assert!(slot.classification(fresh.generation_guard()).is_some());
    assert_eq!(slot.frozen().unwrap().captured_at(), captured_at);
}

#[tokio::test]
async fn read_ahead_is_preserved_and_excludes_review_without_changing_native_deny() {
    let (mut wire, client) = tokio::io::duplex(8192);
    let second = b"GET /second HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    wire.write_all(&[HEADER, second].concat()).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    let provider = RestProvider::default();
    let request = provider
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reader.buffer(), second);
    assert_eq!(slot.frozen().unwrap().buffered_after_header(), second.len());
    let engine = engine();
    let evaluator = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    let native = evaluate_http_l7_request_with_slot(
        &evaluator,
        &context(),
        &config(),
        &request,
        &info(&request),
        slot,
    )
    .unwrap();
    assert!(!native.0);
    assert!(slot.classification(evaluator.generation_guard()).is_none());
    assert!(slot.frozen().is_none());
    assert_eq!(slot.state(), CaptureState::Exchanging);
    // Classification ruled out review. Do not retain Q, or accidentally
    // consume the next request when someone tries to re-enter this exchange.
    assert!(provider.capture_request(reader, slot).await.is_err());
    assert_eq!(request.raw_header, HEADER);
    assert_eq!(reader.buffer(), second);
}

#[tokio::test]
async fn only_completed_exchange_advances_to_the_next_buffered_request() {
    let (mut wire, client) = tokio::io::duplex(8192);
    let second = b"GET /second HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    wire.write_all(&[HEADER, second].concat()).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    let provider = RestProvider::default();
    provider
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    slot.complete_exchange().unwrap();
    assert_eq!(slot.state(), CaptureState::Capturing);
    let next = provider
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.target, "/second");
}

#[tokio::test]
async fn mutated_working_copy_cannot_replace_or_reclassify_frozen_request() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    let mut request = RestProvider::default()
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    request.target = "/different".into();
    let engine = engine();
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    assert!(
        slot.record_classification(
            &guard,
            &request,
            L7DecisionKind::MissingRestAllow,
            RestHitlEligibility::EligibleForReview
        )
        .is_err()
    );
    assert!(slot.classification(&guard).is_none());
    assert_eq!(slot.frozen().unwrap().request().target, "/missing");
}

#[tokio::test]
async fn terminal_is_absorbing_and_shutdown_closes_original_transport() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    RestProvider::default()
        .capture_request(reader, slot)
        .await
        .unwrap();
    session.terminate().await.unwrap();
    session.terminate().await.unwrap();
    let (reader, slot) = session.parts();
    slot.invalidate_classification();
    assert_eq!(slot.state(), CaptureState::Terminal);
    assert!(slot.frozen().is_none());
    assert!(slot.complete_exchange().is_err());
    assert!(
        RestProvider::default()
            .capture_request(reader, slot)
            .await
            .is_err()
    );
    let mut byte = [0];
    assert_eq!(wire.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn cancelled_production_relays_keep_prefix_across_new_policy_evaluator() {
    for selected in [false, true] {
        let engine = engine();
        let (mut wire, client) = tokio::io::duplex(8192);
        let mut session = HttpSession::new(client);
        let (mut upstream, mut relay_upstream) = tokio::io::duplex(8192);
        let prefix = b"GET /missing HTTP/1.1\r\nHost: api.example.test\r";
        wire.write_all(prefix).await.unwrap();
        let cfg = config();
        let configs = [cfg.clone()];
        let ctx = context();
        {
            let evaluator = engine
                .clone_engine_for_tunnel(engine.current_generation())
                .unwrap();
            let borrowed = async {
                if selected {
                    crate::l7::relay::relay_with_route_selection_in_session(
                        &configs,
                        evaluator,
                        &mut session,
                        &mut relay_upstream,
                        &ctx,
                    )
                    .await
                } else {
                    crate::l7::relay::relay_with_inspection_in_session(
                        &cfg,
                        evaluator,
                        &mut session,
                        &mut relay_upstream,
                        &ctx,
                    )
                    .await
                }
            };
            tokio::pin!(borrowed);
            assert!(poll!(borrowed.as_mut()).is_pending());
            engine.reload(POLICY, DATA).unwrap();
            // Same drop performed by the adapter's stale-generation select!.
        }
        assert_eq!(session.slot().partial_header(), prefix);
        wire.write_all(b"\n\r\n").await.unwrap();
        let evaluator = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        if selected {
            crate::l7::relay::relay_with_route_selection_in_session(
                &configs,
                evaluator,
                &mut session,
                &mut relay_upstream,
                &ctx,
            )
            .await
            .unwrap();
        } else {
            crate::l7::relay::relay_with_inspection_in_session(
                &cfg,
                evaluator,
                &mut session,
                &mut relay_upstream,
                &ctx,
            )
            .await
            .unwrap();
        }
        let mut reply = [0; 1024];
        let count = wire.read(&mut reply).await.unwrap();
        assert!(reply[..count].starts_with(b"HTTP/1.1 403"));
        drop(relay_upstream);
        let mut sent = Vec::new();
        upstream.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty());
        assert_eq!(
            session.slot().frozen().unwrap().request().raw_header,
            HEADER
        );
    }
}

#[tokio::test]
async fn stricter_parser_options_revalidate_capture_without_replacing_q() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(b"GET /repos/a%2Fb HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
        .await
        .unwrap();
    let mut session = HttpSession::new(client);
    let permissive = RestProvider::with_options(crate::l7::path::CanonicalizeOptions {
        allow_encoded_slash: true,
        ..Default::default()
    });
    let (reader, slot) = session.parts();
    let original = permissive
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    assert!(
        RestProvider::default()
            .capture_request(reader, slot)
            .await
            .is_err()
    );
    assert_eq!(slot.frozen().unwrap().request(), &original);
    assert_eq!(slot.state(), CaptureState::Frozen);
}

#[tokio::test]
async fn classification_is_engine_bound_and_disabled_reassessment_clears_it() {
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    let request = RestProvider::default()
        .capture_request(reader, slot)
        .await
        .unwrap()
        .unwrap();
    let engine = engine();
    let evaluator = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    evaluate_http_l7_request_with_slot(
        &evaluator,
        &context(),
        &config(),
        &request,
        &info(&request),
        slot,
    )
    .unwrap();
    let foreign = OpaEngine::from_strings(POLICY, DATA).unwrap();
    let foreign_guard = foreign
        .generation_guard(foreign.current_generation())
        .unwrap();
    assert_eq!(
        evaluator.captured_generation(),
        foreign_guard.captured_generation()
    );
    assert!(slot.classification(&foreign_guard).is_none());
    assert!(slot.classification(evaluator.generation_guard()).is_some());
    engine.set_http_hitl_classification_enabled(false);
    assert!(
        !evaluate_http_l7_request_with_slot(
            &evaluator,
            &context(),
            &config(),
            &request,
            &info(&request),
            slot
        )
        .unwrap()
        .0
    );
    assert!(slot.classification(evaluator.generation_guard()).is_none());
    assert!(slot.frozen().is_none());
    assert_eq!(slot.state(), CaptureState::Exchanging);
}

#[tokio::test]
async fn observation_off_keeps_every_partial_boundary_without_a_snapshot() {
    for boundary in 0..HEADER.len() {
        let (mut wire, client) = tokio::io::duplex(8192);
        let mut session = HttpSession::new(client);
        let provider = RestProvider::default();
        wire.write_all(&HEADER[..boundary]).await.unwrap();
        {
            let (reader, slot) = session.parts();
            let capture = provider.capture_request_for_classification(reader, slot, false);
            tokio::pin!(capture);
            assert!(poll!(capture.as_mut()).is_pending());
        }
        assert_eq!(session.slot().partial_header(), &HEADER[..boundary]);
        wire.write_all(&HEADER[boundary..]).await.unwrap();
        let (reader, slot) = session.parts();
        let request = provider
            .capture_request_for_classification(reader, slot, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.raw_header, HEADER);
        assert!(slot.frozen().is_none());
        assert!(slot.partial_header().is_empty());
        assert_eq!(slot.state(), CaptureState::Exchanging);
    }
}

#[tokio::test]
async fn observation_off_moves_header_storage_and_preserves_read_ahead() {
    let (mut wire, client) = tokio::io::duplex(8192);
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    // No eager 4 KiB header allocation for sessions that never parse HTTP.
    assert_eq!(slot.partial_header.capacity(), 0);
    let buffer = slot.capture_buffer().unwrap();
    buffer.reserve(HEADER.len());
    let original_storage = buffer.as_ptr();
    let second = b"GET /allowed HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    wire.write_all(&[HEADER, second].concat()).await.unwrap();
    let provider = RestProvider::default();
    let request = provider
        .capture_request_for_classification(reader, slot, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.raw_header.as_ptr(), original_storage);
    assert_eq!(slot.partial_header.capacity(), 0);
    assert!(slot.frozen().is_none());
    assert_eq!(reader.buffer(), second);
    assert!(
        provider
            .capture_request_for_classification(reader, slot, false)
            .await
            .is_err()
    );
    assert_eq!(reader.buffer(), second);
    // Simulate the native response completing before allowing the next read.
    slot.complete_exchange().unwrap();
    let next = provider
        .capture_request_for_classification(reader, slot, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.target, "/allowed");
    slot.terminate();
    slot.release_snapshot();
    assert!(slot.complete_exchange().is_err());
    assert!(
        provider
            .capture_request_for_classification(reader, slot, false)
            .await
            .is_err()
    );
    assert_eq!(slot.state(), CaptureState::Terminal);
}

#[tokio::test]
async fn non_review_classification_releases_raw_and_canonical_snapshots() {
    for (header, expected_allowed, explicit_deny) in [
        (
            b"GET /allowed HTTP/1.1\r\nHost: api.example.test\r\n\r\n".as_slice(),
            true,
            false,
        ),
        (
            b"GET /missing HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\n\r\n"
                .as_slice(),
            false,
            false,
        ),
        (HEADER, false, true),
    ] {
        let data = if explicit_deny {
            DATA.replace(
                "          - allow: {method: GET, path: /allowed}",
                "          - allow: {method: GET, path: /allowed}\n        deny_rules:\n          - {method: GET, path: /missing}",
            )
        } else {
            DATA.to_string()
        };
        let engine = OpaEngine::from_strings(POLICY, &data).unwrap();
        engine.set_http_hitl_classification_enabled(true);
        let evaluator = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let (mut wire, client) = tokio::io::duplex(8192);
        wire.write_all(header).await.unwrap();
        let mut session = HttpSession::new(client);
        let (reader, slot) = session.parts();
        let request = RestProvider::default()
            .capture_request_for_classification(reader, slot, true)
            .await
            .unwrap()
            .unwrap();
        assert!(slot.frozen().is_some());
        if explicit_deny {
            assert_eq!(
                crate::l7::hitl::evaluate_l7_request_classified(
                    &evaluator,
                    &context(),
                    &info(&request),
                )
                .unwrap()
                .kind,
                L7DecisionKind::ExplicitDeny
            );
        }
        let native = evaluate_http_l7_request_with_slot(
            &evaluator,
            &context(),
            &config(),
            &request,
            &info(&request),
            slot,
        )
        .unwrap();
        assert_eq!(native.0, expected_allowed);
        assert!(slot.frozen().is_none());
        assert!(slot.classification(evaluator.generation_guard()).is_none());
        assert!(slot.partial_header().is_empty());
        assert_eq!(slot.state(), CaptureState::Exchanging);
        assert_eq!(request.raw_header, header);
    }
}

#[tokio::test]
async fn enabling_observation_after_unretained_parse_never_creates_review_authority() {
    let engine = engine();
    engine.set_http_hitl_classification_enabled(false);
    let evaluator = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    let (mut wire, client) = tokio::io::duplex(8192);
    wire.write_all(HEADER).await.unwrap();
    let mut session = HttpSession::new(client);
    let (reader, slot) = session.parts();
    let request = RestProvider::default()
        .capture_request_for_classification(reader, slot, false)
        .await
        .unwrap()
        .unwrap();
    engine.set_http_hitl_classification_enabled(true);
    let native = evaluate_http_l7_request_with_slot(
        &evaluator,
        &context(),
        &config(),
        &request,
        &info(&request),
        slot,
    )
    .unwrap();
    assert!(!native.0);
    assert!(slot.frozen().is_none());
    assert!(slot.classification(evaluator.generation_guard()).is_none());
    assert_eq!(slot.state(), CaptureState::Exchanging);
}

#[tokio::test]
async fn production_relays_do_not_retain_allowed_requests_while_awaiting_response() {
    let header = b"GET /allowed HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    for selected in [false, true] {
        for observation in [false, true] {
            let engine = engine();
            engine.set_http_hitl_classification_enabled(observation);
            let evaluator = engine
                .clone_engine_for_tunnel(engine.current_generation())
                .unwrap();
            let (mut wire, client) = tokio::io::duplex(8192);
            wire.write_all(header).await.unwrap();
            let mut session = HttpSession::new(client);
            let (mut upstream, mut relay_upstream) = tokio::io::duplex(8192);
            let cfg = config();
            let configs = [cfg.clone()];
            let ctx = context();
            {
                let borrowed = async {
                    if selected {
                        crate::l7::relay::relay_with_route_selection_in_session(
                            &configs,
                            evaluator,
                            &mut session,
                            &mut relay_upstream,
                            &ctx,
                        )
                        .await
                    } else {
                        crate::l7::relay::relay_with_inspection_in_session(
                            &cfg,
                            evaluator,
                            &mut session,
                            &mut relay_upstream,
                            &ctx,
                        )
                        .await
                    }
                };
                tokio::pin!(borrowed);
                assert!(poll!(borrowed.as_mut()).is_pending());
                let mut sent = vec![0; header.len()];
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    upstream.read_exact(&mut sent),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(sent, header);
                // Intentionally no response: the exchange is still active.
            }
            assert!(session.slot().frozen().is_none());
            assert!(session.slot().partial_header().is_empty());
            assert_eq!(session.slot().state(), CaptureState::Exchanging);
            session.terminate().await.unwrap();
        }
    }
}

#[tokio::test]
async fn snapshot_choice_keeps_native_canonicalization_and_rejections_identical() {
    for header in [
        b"GET /a/../missing?mode=safe HTTP/1.1\r\nHost: api.example.test\r\n\r\n".as_slice(),
        b"POST /missing HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\n\r\n".as_slice(),
        b"GET /missing HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n".as_slice(),
        b"GET /repos/a%2Fb HTTP/1.1\r\nHost: api.example.test\r\n\r\n".as_slice(),
    ] {
        let mut results = Vec::new();
        for observation in [false, true] {
            let (mut wire, client) = tokio::io::duplex(8192);
            wire.write_all(header).await.unwrap();
            let mut session = HttpSession::new(client);
            let (reader, slot) = session.parts();
            results.push(
                RestProvider::default()
                    .capture_request_for_classification(reader, slot, observation)
                    .await
                    .map_err(|error| error.to_string()),
            );
        }
        assert_eq!(results[0], results[1]);
    }
}

#[tokio::test]
async fn original_tls_object_survives_partial_capture_cancellation() {
    use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa};
    use std::sync::Arc;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(ca.cert_pem())) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let config = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let tls = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let (app, server) = tokio::io::duplex(64 * 1024);
        let (app, server) = tokio::join!(
            crate::l7::tls::tls_connect_upstream(app, "api.example.test", &config),
            crate::l7::tls::tls_terminate_client(server, &tls, "api.example.test"),
        );
        let mut app = app.unwrap();
        let mut session = HttpSession::new(server.unwrap());
        let prefix = b"GET /missing HTTP/1.1\r\nHost: api.example.test\r";
        app.write_all(prefix).await.unwrap();
        app.flush().await.unwrap();
        {
            let (reader, slot) = session.parts();
            let provider = RestProvider::default();
            let capture = provider.capture_request(reader, slot);
            tokio::pin!(capture);
            assert!(matches!(poll!(capture.as_mut()), Poll::Pending));
        }
        assert_eq!(session.slot().partial_header(), prefix);
        app.write_all(b"\n\r\n").await.unwrap();
        app.flush().await.unwrap();
        let (reader, slot) = session.parts();
        let request = RestProvider::default()
            .capture_request(reader, slot)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.raw_header, HEADER);
        reader
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        reader.flush().await.unwrap();
        let mut reply = [0; 128];
        let count = app.read(&mut reply).await.unwrap();
        assert!(reply[..count].starts_with(b"HTTP/1.1 403"));
    })
    .await
    .unwrap();
}
