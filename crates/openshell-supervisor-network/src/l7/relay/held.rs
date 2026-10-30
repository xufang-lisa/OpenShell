// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One-shot relay of an outer-owned, already frozen HTTP HITL request.
//!
//! The caller owns deadline/runtime/client-cancellation fencing and the trusted
//! captured connection identity. This helper neither proves current-executor
//! lifetime nor captures another request, retries, or enters a keep-alive loop.

use super::{
    L7EvalContext, credential_generation_guard, http_response_middleware_relay,
    prepare_inspected_request, reject_credential_resolution, reject_request_authority_mismatch,
    relay_http_request_with_credential_rejection_observed, request_authority_matches_endpoint,
    request_default_port, transformed_body_validator, write_bad_gateway_response,
};
use crate::l7::middleware::{
    MiddlewareApplyResult, apply_middleware_chain_with_request_id, middleware_network_input,
};
use crate::l7::provider::{BodyLength, L7Request, RelayOutcome};
use crate::l7::rest::{CredentialGenerationGuard, WebSocketExtensionMode};
use crate::l7::{EndpointObserver, EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::endpoint_status::EndpointObservationSender;
use openshell_core::secrets;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Admit and relay exactly the supplied bodyless REST request, then return.
#[allow(
    clippy::redundant_pub_crate,
    reason = "Crate-private API is reexported by the parent relay module"
)]
pub(crate) async fn relay_held_rest_once<C, U>(
    request: L7Request,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    engine: &TunnelPolicyEngine,
    config: &L7EndpointConfig,
    request_id: &str,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    if config.protocol != L7Protocol::Rest || config.enforcement != EnforcementMode::Enforce {
        return Err(miette!("held relay requires enforced REST"));
    }
    engine.generation_guard().ensure_current()?;
    let frozen_line = validate_bodyless_request(&request, config)?.to_owned();
    if !request_authority_matches_endpoint(&request, ctx)
        || !matches!(
            crate::l7::rest::request_authority(&request.raw_header, request_default_port(ctx)),
            Ok(Some(_))
        )
    {
        return reject_request_authority_mismatch(client, ctx, &request.action).await;
    }
    let redacted_target = match secrets::redact_target_for_policy(&request.target) {
        Ok(target) if target == request.target => target,
        Ok(_) => {
            return Err(miette!(
                "held request target must not depend on credentials"
            ));
        }
        Err(error) => {
            return reject_credential_resolution(client, ctx, &request.action, &error).await;
        }
    };
    let info = L7RequestInfo {
        action: request.action.clone(),
        target: redacted_target.clone(),
        query_params: request.query_params.clone(),
        graphql: None,
        jsonrpc: None,
    };
    // Admission must precede any live credential snapshot or grant resolution.
    let decision = crate::l7::hitl::evaluate_l7_request_classified(engine, ctx, &info)?;
    engine.generation_guard().ensure_current()?;
    if !decision.allowed {
        return crate::l7::rest::RestProvider::default()
            .deny_with_redacted_target(
                &request,
                &ctx.policy_name,
                &decision.reason,
                client,
                Some(&redacted_target),
                Some(crate::l7::rest::DenyResponseContext::from_l7_context(ctx)),
            )
            .await;
    }

    let chain = engine.query_middleware_chain(&middleware_network_input(ctx))?;
    let response_chain = chain.clone();
    let native_validate = transformed_body_validator(config, engine, ctx, &info);
    let validate = |body: &[u8]| {
        if !body.is_empty() {
            return Ok(Some(
                "held REST middleware must not create a body".to_owned(),
            ));
        }
        native_validate(body)
    };
    let request = match apply_middleware_chain_with_request_id(
        request,
        client,
        ctx,
        chain,
        engine.middleware_runner(),
        engine.generation_guard(),
        openshell_supervisor_middleware::TransformedBodyPolicy::Reevaluate(&validate),
        request_id,
    )
    .await?
    {
        MiddlewareApplyResult::Allowed(request) => request,
        result => {
            let denied = L7Request {
                action: info.action.clone(),
                target: info.target.clone(),
                query_params: info.query_params.clone(),
                raw_header: Vec::new(),
                body_length: BodyLength::None,
            };
            return match result {
                MiddlewareApplyResult::Denied { denial } => {
                    crate::l7::middleware::send_middleware_rejection_response(
                        &denied,
                        client,
                        ctx,
                        denial.as_ref(),
                        &redacted_target,
                    )
                    .await
                }
                MiddlewareApplyResult::AdmissionExhausted => {
                    crate::l7::middleware::send_middleware_admission_exhausted_response(
                        &denied,
                        client,
                        ctx,
                        &redacted_target,
                    )
                    .await
                }
                MiddlewareApplyResult::Allowed(_) => unreachable!(),
            };
        }
    };
    if validate_bodyless_request(&request, config)? != frozen_line
        || request.action != info.action
        || request.target != info.target
        || request.query_params != info.query_params
    {
        return Err(miette!("middleware changed the frozen REST request"));
    }
    if !request_authority_matches_endpoint(&request, ctx) {
        return reject_request_authority_mismatch(client, ctx, &request.action).await;
    }
    engine.generation_guard().ensure_current()?;
    let observation_context = ctx
        .endpoint_observation_tx
        .as_ref()
        .filter(|_| ctx.token_grant_resolver.is_some())
        .and_then(EndpointObservationSender::capture);
    let (request, prepared_ctx) = match prepare_inspected_request(
        request,
        ctx,
        engine,
        config,
        &info,
        request_id,
        observation_context.as_ref(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(refusal) =
                error.downcast_ref::<crate::l7::token_grant_injection::TokenGrantInjectionError>()
            {
                if let Some(observer) = EndpointObserver::begin_captured(
                    ctx.endpoint_observation_tx.as_ref(),
                    config,
                    observation_context.as_ref(),
                    None,
                    Some(engine.generation_guard()),
                ) {
                    observer.observe_token_grant_refusal(refusal, request_id);
                }
                return write_bad_gateway_response(client, Some(request_id)).await;
            }
            return write_bad_gateway_response(client, None).await;
        }
    };
    let ctx = &prepared_ctx;
    let mut guarded = HeldUpstream {
        inner: upstream,
        policy: engine.generation_guard(),
        credentials: credential_generation_guard(ctx),
    };
    let observer = EndpointObserver::begin_captured(
        ctx.endpoint_observation_tx.as_ref(),
        config,
        observation_context.as_ref(),
        ctx.provider_credential_revision,
        Some(engine.generation_guard()),
    );
    let outcome = relay_http_request_with_credential_rejection_observed(
        &request,
        client,
        &mut guarded,
        crate::l7::rest::RelayRequestOptions {
            resolver: ctx.secret_resolver.as_deref(),
            body_classifier: ctx.body_classifier.as_deref(),
            mcp_request_validation: None,
            credential_generation: credential_generation_guard(ctx),
            generation_guard: Some(engine.generation_guard()),
            websocket_extensions: WebSocketExtensionMode::Preserve,
            request_body_credential_rewrite: config.request_body_credential_rewrite,
            deny_uninspected_credentials: config
                .deny_uninspected_body_credentials(ctx.secret_resolver.is_some()),
            credential_signing: config.credential_signing,
            signing_service: &config.signing_service,
            signing_region: &config.signing_region,
            host: &ctx.host,
            port: ctx.port,
        },
        ctx,
        Some(http_response_middleware_relay(
            &request,
            ctx,
            ctx.request_scheme(),
            request_id,
            &response_chain,
            engine.middleware_runner(),
            Some(engine.generation_guard()),
        )),
        observer.as_ref(),
    )
    .await?;
    match outcome {
        None | Some(RelayOutcome::Reusable | RelayOutcome::Consumed) => Ok(()),
        Some(RelayOutcome::Upgraded { .. }) => Err(miette!("held REST relay cannot upgrade")),
    }
}

/// Validate bytes as well as parsed fields without reading the client. A
/// middleware-rebuilt request must still be exactly one bodyless request.
fn validate_bodyless_request<'a>(
    request: &'a L7Request,
    config: &L7EndpointConfig,
) -> Result<&'a str> {
    let raw = &request.raw_header;
    if raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) != Some(raw.len())
        || !matches!(
            request.body_length,
            BodyLength::None | BodyLength::ContentLength(0)
        )
    {
        return Err(miette!(
            "held REST request must be bodyless without read-ahead"
        ));
    }
    crate::l7::rest::validate_http_request_header_block(raw)?;
    let header = std::str::from_utf8(raw).into_diagnostic()?;
    let line = header.split("\r\n").next().unwrap_or_default();
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts.len() != 3
        || parts[0] != request.action
        || parts[2] != "HTTP/1.1"
        || matches!(parts[0], "CONNECT" | "PRI")
    {
        return Err(miette!("invalid frozen REST request line"));
    }
    let (path, suffix) = crate::l7::path::canonicalize_request_target(
        parts[1],
        &crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        },
    )
    .into_diagnostic()?;
    let parsed =
        crate::l7::rest::request_from_buffered_http(parts[0], &path.path, parts[1], raw.clone())?;
    let canonical_target = suffix.map_or_else(
        || path.path.clone(),
        |query| format!("{}?{query}", path.path),
    );
    if path.path != request.target
        || canonical_target != parts[1]
        || parsed.query_params != request.query_params
        || !matches!(
            parsed.body_length,
            BodyLength::None | BodyLength::ContentLength(0)
        )
    {
        return Err(miette!("frozen REST request fields or framing changed"));
    }
    for field in header.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let (name, value) = field
            .split_once(':')
            .ok_or_else(|| miette!("invalid held header"))?;
        if [
            "transfer-encoding",
            "te",
            "expect",
            "upgrade",
            "http2-settings",
        ]
        .iter()
        .any(|blocked| name.eq_ignore_ascii_case(blocked))
            || (name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade")))
        {
            return Err(miette!("held REST request cannot stream or upgrade"));
        }
    }
    Ok(line)
}

/// Native generation checks on *each* poll, including a Pending write/flush
/// being polled again. The outer caller supplies all other lifetime fences.
struct HeldUpstream<'a, U> {
    inner: &'a mut U,
    policy: &'a PolicyGenerationGuard,
    credentials: Option<CredentialGenerationGuard<'a>>,
}

impl<U> HeldUpstream<'_, U> {
    fn check(&self) -> io::Result<()> {
        self.policy
            .ensure_current()
            .map_err(|error| io::Error::other(error.to_string()))?;
        if let Some(guard) = self.credentials {
            guard
                .ensure_current()
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(())
    }
}

impl<U: AsyncRead + Unpin> AsyncRead for HeldUpstream<'_, U> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<U: AsyncWrite + Unpin> AsyncWrite for HeldUpstream<'_, U> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check()?;
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check()?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown is cleanup, not authority to flush or send another request.
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use openshell_core::provider_credentials::ProviderCredentialState;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");
    const DATA: &str = r"
network_policies:
  held_api:
    name: held_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /v1/**
    binaries:
      - { path: /usr/bin/curl }
";

    fn fixture() -> (
        OpaEngine,
        TunnelPolicyEngine,
        L7EndpointConfig,
        L7EvalContext,
    ) {
        let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint.unwrap()).unwrap();
        let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: input.host,
            port: input.port,
            request_default_port: Some(80),
            policy_name: "held_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ..Default::default()
        };
        (engine, tunnel, config, ctx)
    }

    fn request(target: &str) -> L7Request {
        crate::l7::rest::request_from_buffered_http(
            "GET",
            target.split('?').next().unwrap(),
            target,
            format!("GET {target} HTTP/1.1\r\nHost: api.example.test:8080\r\n\r\n").into_bytes(),
        )
        .unwrap()
    }

    #[derive(Default)]
    struct PendingIo {
        writes: usize,
        flushes: usize,
    }

    impl AsyncWrite for PendingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            Poll::Pending
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn pending_write_and_flush_recheck_credential_revision_and_installation() {
        let (_engine, tunnel, _config, _ctx) = fixture();
        for flush in [false, true] {
            // Same-revision repairs must fail the installation fence too.
            for next_revision in [1, 2] {
                let state = ProviderCredentialState::from_child_env_snapshot(1, HashMap::new());
                let snapshot = state.snapshot();
                let mut inner = PendingIo::default();
                let mut guarded = HeldUpstream {
                    inner: &mut inner,
                    policy: tunnel.generation_guard(),
                    credentials: Some(
                        CredentialGenerationGuard::new(&state, 1)
                            .with_installation_id(Some(&snapshot.installation_id)),
                    ),
                };
                let mut cx = Context::from_waker(Waker::noop());
                if flush {
                    assert!(Pin::new(&mut guarded).poll_flush(&mut cx).is_pending());
                } else {
                    assert!(
                        Pin::new(&mut guarded)
                            .poll_write(&mut cx, b"frozen")
                            .is_pending()
                    );
                }
                state.install_child_env_snapshot(next_revision, HashMap::new());
                if flush {
                    assert!(matches!(
                        Pin::new(&mut guarded).poll_flush(&mut cx),
                        Poll::Ready(Err(_))
                    ));
                } else {
                    assert!(matches!(
                        Pin::new(&mut guarded).poll_write(&mut cx, b"frozen"),
                        Poll::Ready(Err(_))
                    ));
                }
                assert_eq!(inner.writes, usize::from(!flush));
                assert_eq!(inner.flushes, usize::from(flush));
            }
        }
    }

    #[test]
    fn pending_write_and_flush_recheck_policy() {
        for flush in [false, true] {
            let (engine, tunnel, _config, _ctx) = fixture();
            let mut inner = PendingIo::default();
            let mut guarded = HeldUpstream {
                inner: &mut inner,
                policy: tunnel.generation_guard(),
                credentials: None,
            };
            let mut cx = Context::from_waker(Waker::noop());
            if flush {
                assert!(Pin::new(&mut guarded).poll_flush(&mut cx).is_pending());
            } else {
                assert!(
                    Pin::new(&mut guarded)
                        .poll_write(&mut cx, b"frozen")
                        .is_pending()
                );
            }
            engine.reload(POLICY, DATA).unwrap();
            assert!(matches!(
                Pin::new(&mut guarded).poll_write(&mut cx, b"frozen"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut guarded).poll_flush(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert_eq!(inner.writes, usize::from(!flush));
            assert_eq!(inner.flushes, usize::from(flush));
        }
    }

    struct NoClientReads(DuplexStream);

    impl AsyncRead for NoClientReads {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("held relay must never read the client");
        }
    }

    impl AsyncWrite for NoClientReads {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn relays_exactly_one_frozen_request_without_keepalive_or_client_reads() {
        let (_engine, tunnel, config, ctx) = fixture();
        let frozen = request("/v1/items?x=one&x=two");
        let (client, mut peer) = tokio::io::duplex(8192);
        let mut client = NoClientReads(client);
        let (mut upstream, mut server) = tokio::io::duplex(8192);
        let next = b"GET /v1/next HTTP/1.1\r\nHost: api.example.test:8080\r\n\r\n";
        peer.write_all(next).await.unwrap();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let relay = relay_held_rest_once(
                frozen,
                &mut client,
                &mut upstream,
                &ctx,
                &tunnel,
                &config,
                "held-one",
            );
            let exchange = async {
                let mut received = Vec::new();
                while !received.ends_with(b"\r\n\r\n") {
                    received.push(server.read_u8().await.unwrap());
                }
                assert!(received.starts_with(b"GET /v1/items?x=one&x=two HTTP/1.1\r\n"));
                server.write_all(response).await.unwrap();
                server.flush().await.unwrap();
                // Deliberately keep both ends open: helper must not wait for EOF
                // or parse the queued next request after this keep-alive response.
            };
            let (result, ()) = tokio::join!(relay, exchange);
            result.unwrap();
        })
        .await
        .unwrap();
        let mut queued = vec![0; next.len()];
        client.0.read_exact(&mut queued).await.unwrap();
        assert_eq!(queued, next);
        let mut output = vec![0; response.len()];
        peer.read_exact(&mut output).await.unwrap();
        assert_eq!(output, response);
        let mut extra = [0; 1];
        let mut read_buf = ReadBuf::new(&mut extra);
        assert!(
            Pin::new(&mut server)
                .poll_read(&mut Context::from_waker(Waker::noop()), &mut read_buf)
                .is_pending()
        );
    }

    #[test]
    fn rejects_body_read_ahead_upgrade_and_inconsistent_fields() {
        let (_engine, _tunnel, config, _ctx) = fixture();
        assert!(validate_bodyless_request(&request("/v1/items?x=1"), &config).is_ok());
        for header in [
            "Content-Length: 1\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Expect: 100-continue\r\n",
            "Upgrade: websocket\r\n",
            "Connection: upgrade\r\n",
        ] {
            let mut req = request("/v1/items");
            req.raw_header =
                format!("GET /v1/items HTTP/1.1\r\nHost: api.example.test:8080\r\n{header}\r\n")
                    .into_bytes();
            assert!(validate_bodyless_request(&req, &config).is_err());
        }
        let mut req = request("/v1/items");
        req.raw_header.extend_from_slice(b"next-or-body");
        assert!(validate_bodyless_request(&req, &config).is_err());
        let mut req = request("/v1/items");
        req.action = "DELETE".into();
        assert!(validate_bodyless_request(&req, &config).is_err());
        let mut req = request("/v1/items");
        req.target = "/v1/other".into();
        assert!(validate_bodyless_request(&req, &config).is_err());
        let mut req = request("/v1/items?x=1");
        req.query_params.clear();
        assert!(validate_bodyless_request(&req, &config).is_err());
    }

    #[tokio::test]
    async fn deny_and_unsupported_modes_never_write_upstream_or_read_client() {
        let (_engine, tunnel, mut config, ctx) = fixture();
        let (client, mut peer) = tokio::io::duplex(8192);
        let mut client = NoClientReads(client);
        let (mut upstream, mut server) = tokio::io::duplex(8192);
        // No resolver is installed: the native policy denial must happen
        // before any credential resolution of this deliberately unresolved header.
        let mut denied = request("/denied");
        denied.raw_header = b"GET /denied HTTP/1.1\r\nHost: api.example.test:8080\r\nAuthorization: Bearer openshell:missing\r\n\r\n".to_vec();
        relay_held_rest_once(
            denied,
            &mut client,
            &mut upstream,
            &ctx,
            &tunnel,
            &config,
            "deny",
        )
        .await
        .unwrap();
        let mut output = [0; 8192];
        let count = peer.read(&mut output).await.unwrap();
        assert!(output[..count].starts_with(b"HTTP/1.1 403"));
        config.enforcement = EnforcementMode::Audit;
        assert!(
            relay_held_rest_once(
                request("/v1/items"),
                &mut client,
                &mut upstream,
                &ctx,
                &tunnel,
                &config,
                "audit"
            )
            .await
            .is_err()
        );
        config.enforcement = EnforcementMode::Enforce;
        config.protocol = L7Protocol::Websocket;
        assert!(
            relay_held_rest_once(
                request("/v1/items"),
                &mut client,
                &mut upstream,
                &ctx,
                &tunnel,
                &config,
                "upgrade"
            )
            .await
            .is_err()
        );
        let mut buf = ReadBuf::new(&mut output);
        assert!(
            Pin::new(&mut server)
                .poll_read(&mut Context::from_waker(Waker::noop()), &mut buf)
                .is_pending()
        );
    }
}
