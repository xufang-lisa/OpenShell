// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{NetworkAction, OpaEngine, PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::endpoint_status::EndpointObservationSender;
use openshell_core::secrets::SecretResolver;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

enum PreparedHttpPolicy {
    Inspect {
        configs: Vec<crate::l7::L7EndpointConfig>,
        evaluator: Box<TunnelPolicyEngine>,
    },
    Passthrough {
        generation_guard: PolicyGenerationGuard,
    },
}

/// Everything an HTTP relay needs after authorization is complete.
///
/// The relay deliberately owns a generation-pinned policy primitive instead
/// of retaining access to the mutable OPA engine. Policy reloads therefore
/// fail closed through the guard or tunnel evaluator already attached here.
pub(super) struct RelayContext<'a> {
    request: &'a L7EvalContext,
    policy: PreparedHttpPolicy,
    middleware_engine: &'a OpaEngine,
}

impl RelayContext<'_> {
    fn generation_guard(&self) -> &PolicyGenerationGuard {
        match &self.policy {
            PreparedHttpPolicy::Inspect { evaluator, .. } => evaluator.generation_guard(),
            PreparedHttpPolicy::Passthrough { generation_guard } => generation_guard,
        }
    }
}

/// Exit reason only, never permission to replay or reuse an upstream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HttpRelayExit {
    Finished,
    PolicyChanged,
}

/// Non-blocking observation channels attached to an authorized HTTP relay.
pub(super) struct RelaySignals {
    /// Receives general sandbox network activity.
    pub(super) activity: Option<ActivitySender>,
    /// Receives terminal tool server results for endpoint status reporting.
    pub(super) endpoint_observation: Option<EndpointObservationSender>,
}

/// Build the request-processing context shared by CONNECT and forward HTTP.
pub(super) fn http_context(
    decision: &EgressDecision,
    provider_credentials: Option<openshell_core::provider_credentials::ProviderCredentialState>,
    secret_resolver: Option<Arc<SecretResolver>>,
    agent_proposals: openshell_core::proposals::AgentProposals,
    workspace: String,
    signals: RelaySignals,
) -> L7EvalContext {
    // Provider-backed credentials must be acquired from the live state for
    // each request after middleware/token-grant awaits. Keep only the legacy
    // resolver fallback when no live provider state exists.
    let secret_resolver = provider_credentials
        .is_none()
        .then_some(secret_resolver)
        .flatten();
    let token_grant_resolver = provider_credentials
        .as_ref()
        .map(|_| crate::l7::token_grant_injection::default_resolver());
    let policy_name = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone().unwrap_or_default(),
        NetworkAction::Deny { .. } => String::new(),
    };

    L7EvalContext {
        host: decision.intent.destination.host.clone(),
        port: decision.intent.destination.port,
        request_default_port: None,
        policy_name,
        binary_path: decision
            .binary
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ancestors: decision
            .ancestors
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        cmdline_paths: decision
            .cmdline_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        secret_resolver,
        provider_credentials,
        provider_credential_revision: None,
        provider_credential_installation_id: None,
        body_classifier: None,
        activity_tx: signals.activity,
        token_grant_resolver,
        agent_proposals,
        workspace,
        endpoint_observation_tx: signals.endpoint_observation,
    }
}

/// Pin a generation for a relay or the forward HTTP single-request path.
pub(super) fn pin_policy_generation(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<PolicyGenerationGuard> {
    opa_engine.generation_guard(expected_generation)
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<TunnelPolicyEngine> {
    opa_engine.clone_engine_for_tunnel(expected_generation)
}

pub(super) fn validate_route_generation(
    route: Option<&L7RouteSnapshot>,
    expected_generation: u64,
) -> Result<()> {
    if let Some(route) = route
        && route.l7_policy_generation != expected_generation
    {
        return Err(miette::miette!(
            "policy changed before CONNECT route hydration \
             [l4_generation:{} l7_generation:{}]",
            expected_generation,
            route.l7_policy_generation,
        ));
    }
    Ok(())
}

/// Prepare a generation-pinned HTTP relay at the adapter boundary.
///
/// A stale generation preserves the established CONNECT behavior: emit the
/// policy-change close event and let the adapter close the live tunnel without
/// attempting to write an HTTP response into it.
pub(super) fn prepare_http_relay<'a>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &'a OpaEngine,
    decision: &EgressDecision,
    request: &'a L7EvalContext,
) -> Option<RelayContext<'a>> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    let policy = if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let evaluator = match pin_l7_evaluator(opa_engine, decision.policy_generation) {
            Ok(evaluator) => evaluator,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        let configs = route
            .configs
            .iter()
            .map(|snapshot| snapshot.config.clone())
            .collect();
        PreparedHttpPolicy::Inspect {
            configs,
            evaluator: Box::new(evaluator),
        }
    } else {
        let generation_guard = match pin_policy_generation(opa_engine, decision.policy_generation) {
            Ok(guard) => guard,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        PreparedHttpPolicy::Passthrough { generation_guard }
    };

    Some(RelayContext {
        request,
        policy,
        middleware_engine: opa_engine,
    })
}

/// Pin the generation used by a raw relay so policy activation or quarantine
/// closes streams that otherwise have no request boundary at which to notice
/// a stale decision.
pub(super) fn prepare_raw_relay(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &OpaEngine,
    decision: &EgressDecision,
) -> Option<PolicyGenerationGuard> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    match pin_policy_generation(opa_engine, decision.policy_generation) {
        Ok(guard) => Some(guard),
        Err(error) => {
            emit_l7_tunnel_close_after_policy_change(
                &decision.intent.destination.host,
                decision.intent.destination.port,
                error,
            );
            None
        }
    }
}

/// Relay an HTTP/1 stream using an already-authorized, generation-pinned context.
///
/// CONNECT plaintext and TLS-terminated streams both enter through this
/// function. Forward HTTP will provide a buffered first request to the same
/// boundary in the next migration step.
pub(super) async fn relay_http_stream<C, U>(
    client: &mut C,
    upstream: &mut U,
    context: RelayContext<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Native caller still closes on policy changes. A future admitted waiter
    // must own the session itself and use the explicit exit-reason boundary.
    let mut session = crate::l7::session::HttpSession::new(client);
    let guard = context.generation_guard().clone();
    let request = context.request;
    if relay_http_stream_in_session(&mut session, upstream, context).await?
        == HttpRelayExit::PolicyChanged
    {
        emit_stale_relay_close(request, &guard);
    }
    Ok(())
}

/// Keep client ownership outside the adapter's own cancellation boundary.
/// A policy change invalidates observation but does not close this session.
/// The caller must not replay after writes or bypass fresh admission: this
/// result carries no authority and deliberately performs no automatic retry.
pub(super) async fn relay_http_stream_in_session<C, U>(
    session: &mut crate::l7::session::HttpSession<C>,
    upstream: &mut U,
    context: RelayContext<'_>,
) -> Result<HttpRelayExit>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let generation_guard = context.generation_guard().clone();
    let result = match context.policy {
        PreparedHttpPolicy::Inspect { configs, evaluator } if configs.len() == 1 => {
            tokio::select! {
                result = crate::l7::relay::relay_with_inspection_in_session(
                    &configs[0],
                    *evaluator,
                    session,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Inspect { configs, evaluator } => {
            tokio::select! {
                result = crate::l7::relay::relay_with_route_selection_in_session(
                    &configs,
                    *evaluator,
                    session,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Passthrough { generation_guard } => {
            let (client, _) = session.parts();
            tokio::select! {
                result = crate::l7::relay::relay_passthrough_with_credentials(
                    client,
                    upstream,
                    context.request,
                    &generation_guard,
                    Some(context.middleware_engine),
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    Ok(())
                }
            }
        }
    };
    result?;
    // Inner protocol guards may also detect stale and return normally. Do not
    // mistake that for a completed exchange merely because select chose it.
    if generation_guard.is_stale() {
        let (_, slot) = session.parts();
        slot.invalidate_classification();
        Ok(HttpRelayExit::PolicyChanged)
    } else {
        Ok(HttpRelayExit::Finished)
    }
}

// Exercise the production single/multiple-route dispatch from L7 fixtures.
#[cfg(test)]
pub async fn relay_inspected_http_stream_for_test<C, U>(
    client: &mut C,
    upstream: &mut U,
    configs: Vec<crate::l7::L7EndpointConfig>,
    evaluator: TunnelPolicyEngine,
    middleware_engine: &OpaEngine,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    relay_http_stream(
        client,
        upstream,
        RelayContext {
            request,
            policy: PreparedHttpPolicy::Inspect {
                configs,
                evaluator: Box::new(evaluator),
            },
            middleware_engine,
        },
    )
    .await
}

/// Relay a policy-authorized raw TCP stream.
pub(super) async fn relay_tcp<C, U>(
    client: &mut C,
    upstream: &mut U,
    generation_guard: &PolicyGenerationGuard,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = tokio::io::copy_bidirectional(client, upstream) => {
            result.into_diagnostic()?;
        }
        () = generation_guard.wait_until_stale() => {
            emit_stale_relay_close(request, generation_guard);
        }
    }
    Ok(())
}

fn emit_stale_relay_close(request: &L7EvalContext, guard: &PolicyGenerationGuard) {
    emit_l7_tunnel_close_after_policy_change(
        &request.host,
        request.port,
        miette::miette!(
            "policy generation is stale [captured_generation:{} current_generation:{}]",
            guard.captured_generation(),
            guard.current_generation(),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::super::{EgressIntent, EndpointDecision, ProcessIdentityEvidence};
    use super::*;

    const POLICY_REGO: &str = include_str!("../../data/sandbox-policy.rego");
    const EMPTY_POLICY_DATA: &str = "network_policies: {}\n";

    fn decision(policy_generation: u64) -> EgressDecision {
        EgressDecision {
            intent: EgressIntent::connect("example.com".to_string(), 80),
            action: NetworkAction::Allow {
                matched_policy: Some("test".to_string()),
            },
            policy_generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::default(),
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    fn request_context() -> L7EvalContext {
        L7EvalContext {
            host: "example.com".to_string(),
            port: 80,
            request_default_port: Some(80),
            policy_name: "test".to_string(),
            binary_path: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: None,
            provider_credential_revision: None,
            provider_credential_installation_id: None,
            body_classifier: None,
            activity_tx: None,
            token_grant_resolver: None,
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            workspace: String::new(),
            endpoint_observation_tx: None,
        }
    }

    fn inspected_context<'a>(
        engine: &'a OpaEngine,
        request: &'a L7EvalContext,
        selected: bool,
    ) -> RelayContext<'a> {
        let config = crate::l7::parse_l7_config(
            &serde_json::from_value(serde_json::json!({
                "protocol": "rest", "enforcement": "enforce"
            }))
            .unwrap(),
        )
        .unwrap();
        RelayContext {
            request,
            policy: PreparedHttpPolicy::Inspect {
                configs: if selected {
                    vec![config; 2]
                } else {
                    vec![config]
                },
                evaluator: Box::new(
                    engine
                        .clone_engine_for_tunnel(engine.current_generation())
                        .unwrap(),
                ),
            },
            middleware_engine: engine,
        }
    }

    #[tokio::test]
    async fn adapter_policy_exit_preserves_partial_client_for_explicit_fresh_reentry() {
        use futures::poll;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for selected in [false, true] {
            let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
            engine.set_http_hitl_classification_enabled(true);
            let request = request_context();
            let (mut wire, client) = tokio::io::duplex(8192);
            let mut session = crate::l7::session::HttpSession::new(client);
            let (mut old_upstream, mut old_peer) = tokio::io::duplex(8192);
            let prefix = b"GET /missing HTTP/1.1\r\nHost: example.com\r";
            wire.write_all(prefix).await.unwrap();
            {
                let context = inspected_context(&engine, &request, selected);
                let exchange = relay_http_stream_in_session(&mut session, &mut old_peer, context);
                tokio::pin!(exchange);
                assert!(poll!(exchange.as_mut()).is_pending());
                engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
                assert_eq!(exchange.await.unwrap(), HttpRelayExit::PolicyChanged);
            }
            assert_eq!(session.slot().partial_header(), prefix);
            assert_eq!(
                session.slot().state(),
                crate::l7::session::CaptureState::Capturing
            );
            drop(old_peer);
            let mut old_bytes = Vec::new();
            old_upstream.read_to_end(&mut old_bytes).await.unwrap();
            assert!(old_bytes.is_empty());

            // The caller supplies both a fresh snapshot and a different
            // upstream, not a retry hidden inside the adapter. Native deny
            // needs no DNS, identity admission or credential resolution.
            let (mut new_upstream, mut new_peer) = tokio::io::duplex(8192);
            wire.write_all(b"\n\r\n").await.unwrap();
            assert_eq!(
                relay_http_stream_in_session(
                    &mut session,
                    &mut new_peer,
                    inspected_context(&engine, &request, selected),
                )
                .await
                .unwrap(),
                HttpRelayExit::Finished
            );
            let mut response = [0; 1024];
            let count = wire.read(&mut response).await.unwrap();
            assert!(response[..count].starts_with(b"HTTP/1.1 403"));
            drop(new_peer);
            let mut new_bytes = Vec::new();
            new_upstream.read_to_end(&mut new_bytes).await.unwrap();
            assert!(new_bytes.is_empty());
            session.terminate().await.unwrap();
        }
    }

    #[tokio::test]
    async fn tls_adapter_policy_exit_keeps_original_handshake_and_reader() {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa};
        use futures::poll;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            let mut session = crate::l7::session::HttpSession::new(client.unwrap());
            let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
            engine.set_http_hitl_classification_enabled(true);
            let request = request_context();
            let (mut upstream, mut peer) = tokio::io::duplex(8192);
            let prefix = b"GET /missing HTTP/1.1\r\nHost: example.com\r";
            wire.write_all(prefix).await.unwrap();
            wire.flush().await.unwrap();
            {
                let context = inspected_context(&engine, &request, false);
                let exchange = relay_http_stream_in_session(&mut session, &mut peer, context);
                tokio::pin!(exchange);
                assert!(poll!(exchange.as_mut()).is_pending());
                engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
                assert_eq!(exchange.await.unwrap(), HttpRelayExit::PolicyChanged);
            }
            assert_eq!(session.slot().partial_header(), prefix);
            drop(peer);
            let mut sent = Vec::new();
            upstream.read_to_end(&mut sent).await.unwrap();
            assert!(sent.is_empty());
            wire.write_all(b"\n\r\n").await.unwrap();
            wire.flush().await.unwrap();
            let (_fresh_upstream, mut fresh_peer) = tokio::io::duplex(8192);
            assert_eq!(
                relay_http_stream_in_session(
                    &mut session,
                    &mut fresh_peer,
                    inspected_context(&engine, &request, false),
                )
                .await
                .unwrap(),
                HttpRelayExit::Finished
            );
            let mut response = [0; 1024];
            let count = wire.read(&mut response).await.unwrap();
            assert!(response[..count].starts_with(b"HTTP/1.1 403"));
            session.terminate().await.unwrap();
            let mut remainder = Vec::new();
            wire.read_to_end(&mut remainder).await.unwrap();
        })
        .await
        .expect("retaining the original TLS stream must not require another handshake");
    }

    #[tokio::test]
    async fn adapter_stale_before_classification_keeps_frozen_q_until_terminal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        engine.set_http_hitl_classification_enabled(true);
        let request = request_context();
        let context = inspected_context(&engine, &request, false);
        let (mut wire, client) = tokio::io::duplex(8192);
        let mut session = crate::l7::session::HttpSession::new(client);
        let header = b"GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n";
        wire.write_all(header).await.unwrap();
        let captured_at = {
            let (reader, slot) = session.parts();
            crate::l7::rest::RestProvider::default()
                .capture_request(reader, slot)
                .await
                .unwrap();
            slot.frozen().unwrap().captured_at()
        };
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let (mut upstream, mut peer) = tokio::io::duplex(8192);
        assert_eq!(
            relay_http_stream_in_session(&mut session, &mut peer, context)
                .await
                .unwrap(),
            HttpRelayExit::PolicyChanged
        );
        let frozen = session.slot().frozen().unwrap();
        assert_eq!(frozen.captured_header(), header);
        assert_eq!(frozen.captured_at(), captured_at);
        assert_eq!(
            session.slot().state(),
            crate::l7::session::CaptureState::Frozen
        );
        drop(peer);
        let mut bytes = Vec::new();
        upstream.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        session.terminate().await.unwrap();
        assert_eq!(
            session.slot().state(),
            crate::l7::session::CaptureState::Terminal
        );
        let mut response = Vec::new();
        wire.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }

    async fn assert_response_lifecycle<C, P>(mut caller: C, mut client: P)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        P: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut upstream, mut server) = tokio::io::duplex(1024);
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let persistent = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        // Larger than either transport buffer: closing must drain the body.
        let body = vec![b'x'; 64 * 1024];
        let mut closing = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        closing.extend_from_slice(&body);
        let relay = Box::pin(relay_http_stream(&mut client, &mut upstream, context));
        let serve = async {
            for response in [persistent.as_slice(), closing.as_slice()] {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                server.write_all(response).await.unwrap();
                server.flush().await.unwrap();
            }
            // Retain the upstream socket: response headers decide persistence.
        };
        let receive = async {
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut first = vec![0; persistent.len()];
            caller.read_exact(&mut first).await.unwrap();
            assert_eq!(first, persistent);
            // A real second exchange verifies reuse, without a timing assertion.
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut second = Vec::new();
            // TLS must return clean EOF, not UnexpectedEof from a dropped socket.
            caller.read_to_end(&mut second).await.unwrap();
            assert_eq!(second, closing);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, (), ()) = tokio::join!(relay, serve, receive);
            result.unwrap();
        })
        .await
        .expect("response delivery and EOF must not await another request");
    }

    #[tokio::test]
    async fn http_relay_reuses_then_closes_after_complete_response() {
        let (caller, client) = tokio::io::duplex(1024);
        assert_response_lifecycle(caller, client).await;
    }

    #[tokio::test]
    async fn tls_http_relay_reuses_then_sends_close_notify_after_complete_response() {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa, tls_terminate_client};
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = Arc::new(
            openshell_crypto::tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let connector = tokio_rustls::TlsConnector::from(config);
        let (caller, client) = tokio::io::duplex(1024);
        let (caller, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                connector.connect(
                    rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                    caller
                ),
                tls_terminate_client(client, &state, "example.com"),
            )
        })
        .await
        .expect("TLS handshake must complete");
        assert_response_lifecycle(caller.unwrap(), client.unwrap()).await;
    }

    #[test]
    fn relay_without_route_pins_l4_decision_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();

        let context = prepare_http_relay(None, &engine, &decision, &request)
            .expect("current L4 generation should prepare a relay");
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        assert_eq!(
            generation_guard.captured_generation(),
            decision.policy_generation
        );
    }

    #[test]
    fn empty_hydrated_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "a current L7 lookup must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn inspected_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![super::super::L7ConfigSnapshot {
                config: crate::l7::L7EndpointConfig {
                    protocol: crate::l7::L7Protocol::Rest,
                    endpoint_id: String::new(),
                    policy_hash: String::new(),
                    path: "/**".to_string(),
                    tls: crate::l7::TlsMode::Auto,
                    enforcement: crate::l7::EnforcementMode::Enforce,
                    graphql_max_body_bytes: crate::l7::graphql::DEFAULT_MAX_BODY_BYTES,
                    json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
                    mcp_strict_tool_names: true,
                    mcp_versions: Vec::new(),
                    allow_encoded_slash: false,
                    websocket_credential_rewrite: false,
                    request_body_credential_rewrite: false,
                    allow_uninspected_credentials: false,
                    provider_credentialed: false,
                    websocket_graphql_policy: false,
                    credential_signing: crate::l7::CredentialSigning::None,
                    signing_service: String::new(),
                    signing_region: String::new(),
                },
            }],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "an inspected route must use the generation that authorized CONNECT"
        );
    }

    #[test]
    fn raw_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };

        assert!(
            prepare_raw_relay(Some(&route), &engine, &decision).is_none(),
            "a raw relay must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn stale_generation_fails_before_relay_context_is_created() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();

        assert!(
            prepare_http_relay(None, &engine, &decision, &request).is_none(),
            "policy reload must prevent a stale relay from starting"
        );
    }

    #[tokio::test]
    async fn raw_relay_closes_immediately_when_fail_closed_generation_is_published() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let request = request_context();
        let (_client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (_upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });
        tokio::task::yield_now().await;

        engine
            .enter_fail_closed("candidate policy validation failed")
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("raw relay should close when its generation becomes stale")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }
}
