// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::wait::WaitEnd;
use crate::l7::{
    L7RequestInfo, hitl,
    session::{CaptureState, HttpSession, RequestSlot},
};
use crate::opa::OpaEngine;
use futures::poll;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncWriteExt;

mod review;

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");
const DATA: &str = r"
network_policies:
  fixture:
    endpoints:
      - host: api.example.test
        ports: [80, 443]
        protocol: rest
        enforcement: enforce
        allowed_ips: [10.0.0.1]
        rules:
          - allow: {method: GET, path: /allowed}
        deny_rules:
          - {method: DELETE, path: /blocked}
    binaries:
      - {path: /usr/bin/parent}
      - {path: /usr/bin/other}
";

fn context() -> L7EvalContext {
    L7EvalContext {
        host: "api.example.test".into(),
        port: 80,
        request_default_port: Some(80),
        policy_name: "fixture".into(),
        binary_path: "/usr/bin/curl".into(),
        ancestors: vec!["/usr/bin/parent".into()],
        cmdline_paths: vec!["/untrusted/argv".into()],
        workspace: "team".into(),
        ..Default::default()
    }
}

fn config() -> L7EndpointConfig {
    let value =
        serde_json::from_value(serde_json::json!({"protocol":"rest", "enforcement":"enforce"}))
            .unwrap();
    crate::l7::parse_l7_config(&value).unwrap()
}

fn frozen_slot(tunnel: &TunnelPolicyEngine, ctx: &L7EvalContext, path: &str) -> RequestSlot {
    let header = format!(
        "GET {path}?secret=query-sentinel HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: header-sentinel\r\nCookie: cookie-sentinel\r\n\r\n"
    );
    let request = crate::l7::rest::request_from_buffered_http(
        "GET",
        path,
        &format!("{path}?secret=query-sentinel"),
        header.into_bytes(),
    )
    .unwrap();
    let mut slot = RequestSlot::new();
    slot.enable_wait_admission();
    slot.freeze(request.clone(), 0).unwrap();
    let info = L7RequestInfo {
        action: request.action.clone(),
        target: request.target.clone(),
        query_params: request.query_params.clone(),
        graphql: None,
        jsonrpc: None,
    };
    assert!(
        !hitl::evaluate_http_l7_request_with_slot(
            tunnel,
            ctx,
            &config(),
            &request,
            &info,
            &mut slot
        )
        .unwrap()
        .0
    );
    slot
}

#[test]
fn http_hitl_input_captures_frozen_path_and_l4_ancestor_not_argv() {
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let ctx = context();
    let slot = frozen_slot(&tunnel, &ctx, "/api/users/42");
    let input = extract(&tunnel, &ctx, &config(), slot.frozen().unwrap()).unwrap();
    assert_eq!(input.method(), "GET");
    assert_eq!(input.path(), "/api/users/42");
    assert_eq!(input.scope().binaries.len(), 1);
    assert_eq!(input.scope().binaries[0].path, "/usr/bin/parent");
    let endpoint = &input.scope().endpoints[0];
    assert_eq!(endpoint.ports, vec![80]);
    assert_eq!(endpoint.allowed_ips, vec!["10.0.0.1"]);
    assert_eq!(endpoint.deny_rules.len(), 1);
    assert!(endpoint.rules.is_empty());
    let metadata = input.review_metadata();
    for secret in [
        "query-sentinel",
        "header-sentinel",
        "cookie-sentinel",
        "/untrusted/argv",
    ] {
        assert!(!metadata.contains(secret), "leaked {secret}");
    }
    assert!(metadata.contains("GET includes HEAD"));
    assert_eq!(
        slot.frozen().unwrap().request().query_params["secret"],
        vec!["query-sentinel"]
    );
}

#[test]
fn http_hitl_literal_subset_rejects_globs_and_ambiguous_paths_without_new_semantics() {
    for path in ["/api/42", "/", "/api/", "/v1/item-id.json"] {
        assert!(native_literal_request("GET", path), "{path}");
    }
    for path in [
        "/a/*",
        "/a/**",
        "/a/[x]",
        "/a/{x,y}",
        "/a\\b",
        "/a?secret=x",
        "/a/%2F",
        "/a//b",
        "/a/../b",
        "/a/;x",
        "relative",
    ] {
        assert!(!native_literal_request("GET", path), "{path}");
    }
    for method in ["*", "X*", "G ET", ""] {
        assert!(!native_literal_request(method, "/a"));
    }
    assert!(
        native_literal_request("get", "/a"),
        "native case semantics are preserved"
    );
}

#[test]
fn http_hitl_input_requires_matching_trusted_owner_and_unambiguous_scope() {
    for data in [
        DATA.replace("/usr/bin/parent", "/usr/bin/*"),
        DATA.replace("host: api.example.test", "host: '*.example.test'"),
        DATA.replace("ports: [80, 443]", "ports: [81, 443]"),
    ] {
        let engine = OpaEngine::from_strings(POLICY, &data).unwrap();
        engine.set_http_hitl_wait_enabled(true);
        let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
        let slot = frozen_slot(&tunnel, &context(), "/missing");
        assert!(
            slot.frozen()
                .is_none_or(|frozen| extract(&tunnel, &context(), &config(), frozen).is_none())
        );
    }
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let slot = frozen_slot(&tunnel, &context(), "/missing");
    for ctx in [
        L7EvalContext {
            workspace: String::new(),
            ..context()
        },
        L7EvalContext {
            policy_name: "wrong-owner".into(),
            ..context()
        },
        L7EvalContext {
            ancestors: vec!["/untrusted/argv".into()],
            ..context()
        },
    ] {
        assert!(extract(&tunnel, &ctx, &config(), slot.frozen().unwrap()).is_none());
    }
    engine.reload(POLICY, DATA).unwrap();
    assert!(extract(&tunnel, &context(), &config(), slot.frozen().unwrap()).is_none());
}

struct Service {
    calls: AtomicUsize,
    mode: usize,
}

#[test]
fn http_hitl_proto_projection_preserves_policy_constraints_and_rejects_mismatched_q() {
    let mut policy =
        openshell_policy::parse_sandbox_policy(&format!("version: 1\n{DATA}")).unwrap();
    policy
        .network_policies
        .get_mut("fixture")
        .unwrap()
        .endpoints[0]
        .advisor_proposed = true;
    let engine = OpaEngine::from_proto(&policy).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let slot = frozen_slot(&tunnel, &context(), "/missing");
    let input = extract(&tunnel, &context(), &config(), slot.frozen().unwrap()).unwrap();
    assert_eq!(
        input.scope().endpoints[0].deny_rules,
        policy.network_policies["fixture"].endpoints[0].deny_rules
    );
    assert_eq!(input.scope().endpoints[0].allowed_ips, vec!["10.0.0.1"]);
    let mut corrupt = slot.frozen().unwrap().request().clone();
    corrupt.query_params.clear();
    let mut corrupt_slot = RequestSlot::new();
    corrupt_slot.freeze(corrupt, 0).unwrap();
    assert!(
        extract(
            &tunnel,
            &context(),
            &config(),
            corrupt_slot.frozen().unwrap()
        )
        .is_none()
    );
}

#[tokio::test]
async fn http_hitl_shared_chunk_keeps_independent_waiter_ids_cancel_and_quota() {
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    engine.set_http_hitl_proposal_service(Arc::new(Service {
        calls: AtomicUsize::new(0),
        mode: 0,
    }));
    let mut sessions = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..2 {
        let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
        let mut slot = frozen_slot(&tunnel, &context(), "/missing");
        assert!(slot.try_begin_wait(&tunnel, "api.example.test", 80));
        let (client, transport) = tokio::io::duplex(8192);
        clients.push(client);
        sessions.push(HttpSession::from_reader(
            tokio::io::BufReader::new(transport),
            slot,
        ));
    }
    assert_ne!(
        sessions[0].slot().review_request_id(),
        sessions[1].slot().review_request_id()
    );
    // Drop each borrowed poll future, not its owning session: ack remains
    // associated locally, and neither waiter acquires upstream authority.
    for session in &mut sessions {
        let waiting = session.wait_no_release();
        tokio::pin!(waiting);
        assert!(poll!(waiting.as_mut()).is_pending());
    }
    assert_eq!(
        sessions[0].slot().submitted_proposal(),
        Some("accepted-chunk")
    );
    assert_eq!(
        sessions[1].slot().submitted_proposal(),
        Some("accepted-chunk")
    );
    clients[0].shutdown().await.unwrap();
    assert_eq!(
        sessions[0].wait_no_release().await,
        Some(WaitEnd::ClientClosed)
    );
    drop(sessions.remove(0));
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    assert_eq!(sessions[0].slot().state(), CaptureState::PendingReview);
    engine.set_http_hitl_wait_enabled(false);
    assert_eq!(sessions[0].wait_no_release().await, Some(WaitEnd::Disabled));
    drop(sessions);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
}
impl HeldProposalService for Service {
    fn submit<'a>(&'a self, input: &'a HeldProposalInput) -> ProposalSubmission<'a> {
        Box::pin(async move {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(input.path(), "/missing");
            match self.mode {
                1 => std::future::pending().await,
                2 if attempt == 0 => Err(ProposalSubmitError::Retryable),
                3 => Err(ProposalSubmitError::Unavailable),
                _ => Ok("accepted-chunk".into()),
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn http_hitl_submission_has_original_deadline_and_retains_ack_without_release() {
    for mode in [0, 1, 2, 3] {
        let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
        engine.set_http_hitl_wait_enabled(true);
        let service = Arc::new(Service {
            calls: AtomicUsize::new(0),
            mode,
        });
        engine.set_http_hitl_proposal_service(service.clone());
        let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
        let mut slot = frozen_slot(&tunnel, &context(), "/missing");
        assert!(slot.try_begin_wait(&tunnel, "api.example.test", 80));
        let (mut client, transport) = tokio::io::duplex(8192);
        let mut session = HttpSession::from_reader(tokio::io::BufReader::new(transport), slot);
        tokio::time::advance(std::time::Duration::from_secs(290)).await;
        if mode == 3 {
            assert_eq!(
                session.wait_no_release().await,
                Some(WaitEnd::ProposalUnavailable)
            );
        } else {
            {
                let waiting = session.wait_no_release();
                tokio::pin!(waiting);
                assert!(poll!(waiting.as_mut()).is_pending());
                engine.reload(POLICY, DATA).unwrap();
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
                assert!(poll!(waiting.as_mut()).is_pending());
                tokio::time::advance(std::time::Duration::from_secs(8)).await;
                assert_eq!(waiting.await, Some(WaitEnd::Deadline));
            }
            assert_eq!(
                session.slot().submitted_proposal(),
                if mode == 1 {
                    None
                } else {
                    Some("accepted-chunk")
                }
            );
        }
        assert_eq!(session.slot().state(), CaptureState::Terminal);
        // Reservation lives until real transport drop, even on submission failure.
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        drop(session);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut bytes)
            .await
            .unwrap();
        assert!(bytes.is_empty());
    }
}

#[tokio::test]
async fn http_hitl_disconnect_and_extra_input_cancel_stalled_submission() {
    for extra in [false, true] {
        let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
        engine.set_http_hitl_wait_enabled(true);
        let service = Arc::new(Service {
            calls: AtomicUsize::new(0),
            mode: 1,
        });
        engine.set_http_hitl_proposal_service(service.clone());
        let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
        let mut slot = frozen_slot(&tunnel, &context(), "/missing");
        assert!(slot.try_begin_wait(&tunnel, "api.example.test", 80));
        let (mut client, transport) = tokio::io::duplex(8192);
        let mut session = HttpSession::from_reader(tokio::io::BufReader::new(transport), slot);
        let waiting = session.wait_no_release();
        tokio::pin!(waiting);
        assert!(poll!(waiting.as_mut()).is_pending());
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
        if extra {
            client.write_all(b"extra").await.unwrap();
        } else {
            client.shutdown().await.unwrap();
        }
        assert_eq!(
            waiting.await,
            Some(if extra {
                WaitEnd::ExtraInput
            } else {
                WaitEnd::ClientClosed
            })
        );
    }
}

fn provider_projection_fixture(credentialed: bool) -> SandboxPolicy {
    let mut policy = openshell_policy::parse_sandbox_policy(
        r#"
version: 1
network_policies:
  _provider_oc_company:
    endpoints:
      - host: 10.239.168.89
        port: 11434
        path: /v3/**
        protocol: rest
        enforcement: enforce
        allowed_ips: [10.239.168.89/32]
        rules:
          - allow: {method: POST, path: /v3/chat/completions}
        deny_rules:
          - {method: DELETE, path: /v3/blocked}
    binaries:
      - {path: /usr/local/bin/node}
"#,
    )
    .unwrap();
    let rule = policy
        .network_policies
        .get_mut("_provider_oc_company")
        .unwrap();
    let endpoint = &mut rule.endpoints[0];
    endpoint.provider_credentialed = credentialed;
    endpoint.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
    endpoint.credential_binding = Some(openshell_core::proto::NetworkCredentialBinding {
        provider: "synthetic-provider".into(),
    });
    endpoint.request_body_credential_rewrite = true;
    endpoint.allow_encoded_slash = true;
    let mut unrelated = endpoint.clone();
    unrelated.host = "other.example.test".into();
    unrelated.provider_credentialed = !credentialed;
    // Keep the held destination second to catch reattaching provenance only
    // after filtering, which would bind the first endpoint's owner instead.
    rule.endpoints.insert(0, unrelated);
    let owners = openshell_core::policy_identity::provider_token_grant_owners(
        "synthetic-provider-record",
        rule,
    );
    assert_eq!(owners.len(), rule.endpoints.len());
    for (endpoint, owner) in rule.endpoints.iter_mut().zip(owners) {
        endpoint.token_grant_owner = owner;
    }
    policy
}

#[test]
fn http_hitl_provider_projection_preserves_constraints_and_enters_wait() {
    // In-process only: no sockets, Gateway, upstream calls or approvals.
    for credentialed in [false, true] {
        let policy = provider_projection_fixture(credentialed);
        let mut expected = policy.network_policies["_provider_oc_company"].endpoints[1].clone();
        expected.rules.clear();
        expected.access = 0;
        expected.advisor_proposed = true;
        let engine = OpaEngine::from_proto(&policy).unwrap();
        engine.set_http_hitl_wait_enabled(true);
        let service = Arc::new(Service {
            calls: AtomicUsize::new(0),
            mode: 0,
        });
        engine.set_http_hitl_proposal_service(service.clone());
        let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
        let data_before = {
            let opa = tunnel.engine().lock().unwrap();
            serde_json::to_value(opa.get_data()).unwrap()
        };
        let endpoint = serde_json::from_value(
            data_before["network_policies"]["_provider_oc_company"]["endpoints"][1].clone(),
        )
        .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint).unwrap();
        let ctx = L7EvalContext {
            host: "10.239.168.89".into(),
            port: 11434,
            request_default_port: Some(80),
            workspace: "default".into(),
            policy_name: "_provider_oc_company".into(),
            binary_path: "/usr/local/bin/node".into(),
            ..Default::default()
        };
        let request = crate::l7::rest::request_from_buffered_http(
            "GET",
            "/v3/models",
            "/v3/models?probe=query-sentinel",
            b"GET /v3/models?probe=query-sentinel HTTP/1.1\r\nHost: 10.239.168.89:11434\r\nConnection: keep-alive\r\n\r\n".to_vec(),
        )
        .unwrap();
        let info = L7RequestInfo {
            action: request.action.clone(),
            target: request.target.clone(),
            query_params: request.query_params.clone(),
            graphql: None,
            jsonrpc: None,
        };
        let mut slot = RequestSlot::new();
        slot.enable_wait_admission();
        slot.freeze(request.clone(), 0).unwrap();
        assert!(
            !hitl::evaluate_http_l7_request_with_slot(
                &tunnel, &ctx, &config, &request, &info, &mut slot,
            )
            .unwrap()
            .0
        );
        assert_eq!(
            slot.classification(tunnel.generation_guard())
                .unwrap()
                .eligibility,
            hitl::RestHitlEligibility::EligibleForReview
        );
        let input = extract(&tunnel, &ctx, &config, slot.frozen().unwrap()).unwrap();
        assert_eq!(input.scope().endpoints, vec![expected.clone()]);
        assert_eq!(
            input.scope().binaries,
            policy.network_policies["_provider_oc_company"].binaries
        );
        assert_eq!(input.path(), "/v3/models");
        assert_eq!(slot.held_input().unwrap().scope(), input.scope());
        for excluded in ["query-sentinel", expected.token_grant_owner.as_str()] {
            assert!(!input.review_metadata().contains(excluded));
        }
        let data_after = {
            let opa = tunnel.engine().lock().unwrap();
            serde_json::to_value(opa.get_data()).unwrap()
        };
        assert_eq!(data_before, data_after);
        assert!(slot.try_begin_wait(&tunnel, &ctx.host, ctx.port));
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        assert_eq!(service.calls.load(Ordering::SeqCst), 0);
        drop(slot);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    }
}

#[test]
fn http_hitl_provider_projection_rejects_invalid_or_unknown_metadata() {
    let policy = provider_projection_fixture(false);
    let engine = OpaEngine::from_proto(&policy).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let data = {
        let opa = tunnel.engine().lock().unwrap();
        serde_json::to_value(opa.get_data()).unwrap()
    };
    let source = &data["network_policies"]["_provider_oc_company"];
    // L7 loading already checks types; detached clones also verify that the
    // projection boundary never silently drops malformed or unknown fields.
    for (field, value) in [
        ("provider_credentialed", serde_json::json!("not-a-boolean")),
        ("provider_credentialed", serde_json::Value::Null),
        ("token_grant_owner", serde_json::json!(true)),
        ("token_grant_owner", serde_json::Value::Null),
        ("unsupported_runtime_marker", serde_json::json!(true)),
    ] {
        let mut rule = source.clone();
        rule["endpoints"][1][field] = value;
        assert!(project_runtime_rule(rule, "_provider_oc_company").is_none());
    }
    let mut defaults = source.clone();
    for endpoint in defaults["endpoints"].as_array_mut().unwrap() {
        let object = endpoint.as_object_mut().unwrap();
        object.remove("provider_credentialed");
        object.remove("token_grant_owner");
    }
    let scope = project_runtime_rule(defaults, "_provider_oc_company").unwrap();
    assert!(scope.endpoints.iter().all(|endpoint| {
        !endpoint.provider_credentialed && endpoint.token_grant_owner.is_empty()
    }));
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
}
