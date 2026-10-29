// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::provider::L7Provider;
use crate::opa::OpaEngine;
use std::collections::HashMap;
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
          - allow: {method: GET, path: '/glob/**'}
          - allow:
              method: GET
              path: /query
              query: {mode: {glob: safe}}
        deny_rules:
          - {method: GET, path: /blocked}
          - {method: GET, path: /query, query: {mode: {glob: forbidden}}}
    binaries:
      - {path: /usr/bin/curl}
"#;

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
    let value =
        serde_json::from_value(serde_json::json!({"protocol": "rest", "enforcement": "enforce"}))
            .unwrap();
    crate::l7::parse_l7_config(&value).unwrap()
}

fn request(method: &str, path: &str, headers: &str) -> L7Request {
    L7Request {
        action: method.into(),
        target: path.into(),
        query_params: HashMap::new(),
        raw_header: format!("{method} {path} HTTP/1.1\r\nHost: api.example.test\r\n{headers}\r\n")
            .into_bytes(),
        body_length: BodyLength::None,
    }
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

fn engine(data: &str) -> (OpaEngine, TunnelPolicyEngine) {
    let engine = OpaEngine::from_strings(POLICY, data).unwrap();
    let tunnel = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    (engine, tunnel)
}

#[test]
fn native_allow_missing_deny_and_query_constraints_are_distinct() {
    let (_, tunnel) = engine(DATA);
    let ctx = context();
    for (method, target, values, expected) in [
        ("GET", "/allowed", vec![], L7DecisionKind::Allowed),
        ("HEAD", "/allowed", vec![], L7DecisionKind::Allowed),
        ("get", "/allowed", vec![], L7DecisionKind::Allowed),
        ("GET", "/glob/a/b", vec![], L7DecisionKind::Allowed),
        ("POST", "/allowed", vec![], L7DecisionKind::MissingRestAllow),
        ("GET", "/missing", vec![], L7DecisionKind::MissingRestAllow),
        ("GET", "/blocked", vec![], L7DecisionKind::ExplicitDeny),
        ("GET", "/query", vec!["safe"], L7DecisionKind::Allowed),
        ("GET", "/query", vec![], L7DecisionKind::ConstraintFailed),
        ("GET", "/query", vec![""], L7DecisionKind::ConstraintFailed),
        (
            "GET",
            "/query",
            vec!["bad"],
            L7DecisionKind::ConstraintFailed,
        ),
        (
            "GET",
            "/query",
            vec!["safe", "bad"],
            L7DecisionKind::ConstraintFailed,
        ),
        (
            "GET",
            "/query",
            vec!["forbidden"],
            L7DecisionKind::ExplicitDeny,
        ),
    ] {
        let mut req = request(method, target, "");
        if !values.is_empty() {
            req.query_params.insert(
                "mode".into(),
                values.into_iter().map(str::to_string).collect(),
            );
        }
        let decision = evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).unwrap();
        assert_eq!(decision.kind, expected, "{method} {target}");
        let native = crate::l7::relay::evaluate_l7_request(&tunnel, &ctx, &info(&req)).unwrap();
        assert_eq!((decision.allowed, decision.reason.clone()), native);
        let eligibility =
            assess_rest_hitl_candidate(true, true, &config(), &ctx, &req, Ok(&decision));
        assert_eq!(
            eligibility == RestHitlEligibility::EligibleForReview,
            expected == L7DecisionKind::MissingRestAllow
        );
    }
}

#[test]
fn deny_wins_across_overlapping_endpoints_and_policies() {
    let data = format!(
        "{DATA}\n  sibling:\n    endpoints:\n      - host: api.example.test\n        port: 80\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: {{method: '*', path: '**'}}\n    binaries:\n      - {{path: /usr/bin/curl}}\n"
    );
    let (_, tunnel) = engine(&data);
    for (target, kind) in [
        ("/blocked", L7DecisionKind::ExplicitDeny),
        ("/query", L7DecisionKind::Allowed),
    ] {
        let req = request("GET", target, "");
        assert_eq!(
            evaluate_l7_request_classified(&tunnel, &context(), &info(&req))
                .unwrap()
                .kind,
            kind
        );
    }
}

#[test]
fn l4_endpoint_port_and_binary_failures_never_qualify() {
    let (_, tunnel) = engine(DATA);
    for ctx in [
        L7EvalContext {
            host: "other.example.test".into(),
            ..context()
        },
        L7EvalContext {
            port: 81,
            ..context()
        },
        L7EvalContext {
            binary_path: "/usr/bin/other".into(),
            ..context()
        },
    ] {
        let req = request("GET", "/missing", "");
        let decision = evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).unwrap();
        assert_eq!(decision.kind, L7DecisionKind::L4Denied);
        assert_eq!(
            assess_rest_hitl_candidate(true, true, &config(), &ctx, &req, Ok(&decision)),
            RestHitlEligibility::Ineligible(RestHitlIneligibleReason::L4Denied)
        );
    }
}

#[test]
fn endpoint_path_miss_is_not_a_missing_rest_rule() {
    let (_, tunnel) =
        engine(&DATA.replace("protocol: rest", "protocol: rest\n        path: /scoped/**"));
    let req = request("GET", "/missing", "");
    let decision = evaluate_l7_request_classified(&tunnel, &context(), &info(&req)).unwrap();
    assert_eq!(decision.kind, L7DecisionKind::OtherPolicyDeny);
}

#[test]
fn sibling_websocket_query_failure_is_not_missing_rest_allow() {
    let data = format!(
        "{DATA}\n  sibling:\n    endpoints:\n      - host: api.example.test\n        port: 80\n        protocol: websocket\n        enforcement: enforce\n        rules:\n          - allow:\n              method: GET\n              path: /missing\n              query: {{mode: {{glob: safe}}}}\n    binaries:\n      - {{path: /usr/bin/curl}}\n"
    );
    let (_, tunnel) = engine(&data);
    let req = request("GET", "/missing", "");
    assert_eq!(
        evaluate_l7_request_classified(&tunnel, &context(), &info(&req))
            .unwrap()
            .kind,
        L7DecisionKind::ConstraintFailed
    );
}

#[test]
fn custom_policy_without_fact_contract_preserves_native_decision() {
    for allowed in [true, false] {
        let policy = format!(
            "package openshell.sandbox\nallow_request := {allowed}\nrequest_deny_reason := \"custom deny\"\n"
        );
        let opa = OpaEngine::from_strings(&policy, DATA).unwrap();
        opa.set_http_hitl_classification_enabled(true);
        let tunnel = opa
            .clone_engine_for_tunnel(opa.current_generation())
            .unwrap();
        let req = request("GET", "/missing", "");
        assert!(evaluate_l7_request_classified(&tunnel, &context(), &info(&req)).is_err());
        assert_eq!(
            evaluate_http_l7_request(&tunnel, &context(), &config(), &req, &info(&req))
                .unwrap()
                .0,
            allowed
        );
    }
}

#[test]
fn contradictory_custom_facts_never_replace_native_authorization() {
    for allowed in [true, false] {
        let opposite = !allowed;
        let policy = format!(
            "package openshell.sandbox\nallow_request := {allowed}\nrequest_deny_reason := \"native diagnostic\"\nrequest_authorization := {{\"allowed\": {opposite}, \"l4_allowed\": true, \"binary_identity_required\": true, \"explicit_deny\": false, \"rest_endpoint\": true, \"rest_shape_matched\": false, \"reason\": \"unrelated diagnostic\"}}\n"
        );
        let opa = OpaEngine::from_strings(&policy, DATA).unwrap();
        opa.set_http_hitl_classification_enabled(true);
        let tunnel = opa
            .clone_engine_for_tunnel(opa.current_generation())
            .unwrap();
        let req = request("GET", "/missing", "");
        let actual =
            evaluate_http_l7_request(&tunnel, &context(), &config(), &req, &info(&req)).unwrap();
        assert_eq!(actual.0, allowed);
        assert_eq!(actual.1, if allowed { "" } else { "native diagnostic" });
    }
}

#[test]
fn eligibility_is_default_off_live_toggle_is_shared_with_existing_tunnel() {
    let (opa, tunnel) = engine(DATA);
    let req = request("GET", "/missing", "");
    let ctx = context();
    let decision = evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).unwrap();
    assert!(!tunnel.http_hitl_classification_enabled());
    assert_eq!(
        assess_rest_hitl_candidate(
            tunnel.http_hitl_classification_enabled(),
            true,
            &config(),
            &ctx,
            &req,
            Ok(&decision)
        ),
        RestHitlEligibility::Ineligible(RestHitlIneligibleReason::Disabled)
    );
    opa.set_http_hitl_classification_enabled(true);
    assert!(tunnel.http_hitl_classification_enabled());
    assert_eq!(
        assess_rest_hitl_candidate(
            tunnel.http_hitl_classification_enabled(),
            true,
            &config(),
            &ctx,
            &req,
            Ok(&decision)
        ),
        RestHitlEligibility::EligibleForReview
    );
    opa.set_http_hitl_classification_enabled(false);
    assert!(!tunnel.http_hitl_classification_enabled());
    // Both flag states still produce native denial, never a forwarding grant.
    for enabled in [false, true] {
        opa.set_http_hitl_classification_enabled(enabled);
        assert!(
            !evaluate_http_l7_request(&tunnel, &ctx, &config(), &req, &info(&req))
                .unwrap()
                .0
        );
    }
}

#[test]
fn unsupported_headers_bodies_and_framing_never_qualify() {
    use RestHitlIneligibleReason as No;
    for (headers, expected) in [
        ("Transfer-Encoding: chunked\r\n", No::TransferEncoding),
        ("tRaNsFeR-EnCoDiNg:\r\n", No::TransferEncoding),
        ("TE: trailers\r\n", No::TransferEncoding),
        ("Expect: 100-continue\r\n", No::Expect),
        ("Expect:\r\n", No::Expect),
        ("Upgrade: websocket\r\n", No::Upgrade),
        ("Connection: keep-alive, Upgrade\r\n", No::Upgrade),
        ("HTTP2-Settings: xxx\r\n", No::Upgrade),
        ("Content-Length: 1\r\n", No::RequestBody),
        (
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            No::InvalidFraming,
        ),
        ("Content-Length: bad\r\n", No::InvalidFraming),
    ] {
        assert_eq!(
            supported_request_shape(&request("GET", "/missing", headers)),
            Err(expected),
            "{headers}"
        );
    }
    for method in ["GET", "HEAD", "POST", "DELETE"] {
        assert!(supported_request_shape(&request(method, "/missing", "")).is_ok());
        assert!(
            supported_request_shape(&request(method, "/missing", "Content-Length: 0\r\n")).is_ok()
        );
    }
    let mut req = request("GET", "/missing", "");
    req.body_length = BodyLength::ContentLength(1);
    assert_eq!(supported_request_shape(&req), Err(No::RequestBody));
    req.body_length = BodyLength::Chunked;
    assert_eq!(supported_request_shape(&req), Err(No::RequestBody));
    req.body_length = BodyLength::None;
    req.raw_header
        .extend_from_slice(b"GET /smuggled HTTP/1.1\r\n\r\n");
    assert_eq!(supported_request_shape(&req), Err(No::InvalidFraming));
    for (raw, expected) in [
        (
            "GET /missing HTTP/1.0\r\nHost: api.example.test\r\n\r\n",
            No::UnsupportedHttpVersion,
        ),
        // HTTP/2 is already rejected by native HTTP/1 header validation.
        (
            "GET /missing HTTP/2.0\r\nHost: api.example.test\r\n\r\n",
            No::InvalidFraming,
        ),
        (
            "GET /missing HTTP/1.1 extra\r\nHost: api.example.test\r\n\r\n",
            No::InvalidFraming,
        ),
        (
            "GET /missing HTTP/1.1\r\n bad: fold\r\n\r\n",
            No::InvalidFraming,
        ),
    ] {
        let mut req = request("GET", "/missing", "");
        req.raw_header = raw.as_bytes().to_vec();
        assert_eq!(supported_request_shape(&req), Err(expected));
    }
}

#[test]
fn unsupported_protocol_audit_authority_and_credential_targets_are_rejected() {
    use RestHitlIneligibleReason as No;
    let (_, tunnel) = engine(DATA);
    let ctx = context();
    let req = request("GET", "/missing", "");
    let decision = evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).unwrap();
    let mut cfg = config();
    cfg.protocol = L7Protocol::Websocket;
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &cfg, &ctx, &req, Ok(&decision)),
        RestHitlEligibility::Ineligible(No::UnsupportedProtocol)
    );
    cfg = config();
    cfg.enforcement = EnforcementMode::Audit;
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &cfg, &ctx, &req, Ok(&decision)),
        RestHitlEligibility::Ineligible(No::AuditMode)
    );
    for host in ["other.example.test", "api.example.test:81"] {
        let mut bad = request("GET", "/missing", "");
        bad.raw_header = format!("GET /missing HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
        assert_eq!(
            assess_rest_hitl_candidate(true, true, &config(), &ctx, &bad, Ok(&decision)),
            RestHitlEligibility::Ineligible(No::AuthorityMismatch)
        );
    }
    for host in ["API.EXAMPLE.TEST", "api.example.test:80"] {
        let mut equivalent = request("GET", "/missing", "");
        equivalent.raw_header =
            format!("GET /missing HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
        assert_eq!(
            assess_rest_hitl_candidate(true, true, &config(), &ctx, &equivalent, Ok(&decision)),
            RestHitlEligibility::EligibleForReview
        );
    }
    let mut missing = request("GET", "/missing", "");
    missing.raw_header = b"GET /missing HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &config(), &ctx, &missing, Ok(&decision)),
        RestHitlEligibility::Ineligible(No::AuthorityMismatch)
    );
    let mut no_identity = decision.clone();
    no_identity.binary_identity_required = false;
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &config(), &ctx, &req, Ok(&no_identity)),
        RestHitlEligibility::Ineligible(No::BinaryIdentityUnavailable)
    );
    let placeholder = request("GET", "/openshell:resolve:env:TEST_TOKEN", "");
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &config(), &ctx, &placeholder, Ok(&decision)),
        RestHitlEligibility::Ineligible(No::CredentialDependentTarget)
    );
}

#[test]
fn stale_error_and_malformed_policy_results_fail_closed() {
    let (opa, tunnel) = engine(DATA);
    let ctx = context();
    let req = request("GET", "/missing", "");
    let decision = evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).unwrap();
    opa.reload(POLICY, DATA).unwrap();
    assert!(evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).is_err());
    assert_eq!(
        assess_rest_hitl_candidate(
            true,
            !tunnel.is_stale(),
            &config(),
            &ctx,
            &req,
            Ok(&decision)
        ),
        RestHitlEligibility::Ineligible(RestHitlIneligibleReason::StalePolicy)
    );
    let error = miette!("injected evaluation failure");
    assert_eq!(
        assess_rest_hitl_candidate(true, true, &config(), &ctx, &req, Err(&error)),
        RestHitlEligibility::Ineligible(RestHitlIneligibleReason::EvaluationError)
    );
    for policy in [
        "package openshell.sandbox\nallow_request := false\n",
        "package openshell.sandbox\nrequest_authorization := {\"allowed\": false}\n",
        "package openshell.sandbox\nrequest_authorization := true\n",
    ] {
        let opa = OpaEngine::from_strings(policy, DATA).unwrap();
        let tunnel = opa
            .clone_engine_for_tunnel(opa.current_generation())
            .unwrap();
        assert!(evaluate_l7_request_classified(&tunnel, &ctx, &info(&req)).is_err());
    }
}

#[tokio::test]
async fn parsed_query_duplicates_retain_native_constraint_failure() {
    let (mut wire, mut stream) = tokio::io::duplex(4096);
    wire.write_all(b"GET /query?mode=safe&mode=bad HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
        .await
        .unwrap();
    drop(wire);
    let req = crate::l7::rest::RestProvider::default()
        .parse_request(&mut stream)
        .await
        .unwrap()
        .unwrap();
    let (_, tunnel) = engine(DATA);
    assert_eq!(req.query_params["mode"], ["safe", "bad"]);
    assert_eq!(
        evaluate_l7_request_classified(&tunnel, &context(), &info(&req))
            .unwrap()
            .kind,
        L7DecisionKind::ConstraintFailed
    );
}

#[tokio::test]
async fn classification_enabled_still_returns_403_and_writes_no_upstream_http() {
    for route_selected in [false, true] {
        let (opa, tunnel) = engine(DATA);
        opa.set_http_hitl_classification_enabled(true);
        let (mut client, mut relay_client) = tokio::io::duplex(8192);
        let (mut upstream, mut relay_upstream) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            if route_selected {
                crate::l7::relay::relay_with_route_selection(
                    &[config()],
                    tunnel,
                    &mut relay_client,
                    &mut relay_upstream,
                    &context(),
                )
                .await
            } else {
                crate::l7::relay::relay_with_inspection(
                    &config(),
                    tunnel,
                    &mut relay_client,
                    &mut relay_upstream,
                    &context(),
                )
                .await
            }
        });
        client
            .write_all(&request("GET", "/missing", "").raw_header)
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));
        let mut sent = Vec::new();
        upstream.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty());
    }
}
