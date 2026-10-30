// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal held-request intent. No request bytes, query values, headers,
//! credentials, client command line, or execution authority cross this seam.

use super::relay::L7EvalContext;
use super::{L7EndpointConfig, session::FrozenRequest};
use crate::opa::TunnelPolicyEngine;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy};
use std::{future::Future, pin::Pin};

/// A snapshot of the classified request and its generation-pinned L4 scope.
/// Intentionally not Debug/Serialize: paths can themselves be sensitive.
#[derive(Clone)]
pub struct HeldProposalInput {
    scope: NetworkPolicyRule,
    method: String,
    path: String,
    binary: String,
    ancestors: Vec<String>,
    workspace: String,
    generation: u64,
    policy_hash: String,
    source_policy: String,
}

impl HeldProposalInput {
    /// Captured trusted connection identity for the limited MVP, not proof of
    /// the current executor. Never include argv as an authorization fallback.
    pub(crate) fn captured_network_input(&self) -> Option<crate::opa::NetworkInput> {
        let endpoint = self.scope.endpoints.first()?;
        let [port] = endpoint.ports.as_slice() else {
            return None;
        };
        Some(crate::opa::NetworkInput {
            host: endpoint.host.clone(),
            port: u16::try_from(*port).ok()?,
            binary_path: self.binary.clone().into(),
            binary_sha256: String::new(),
            ancestors: self.ancestors.iter().map(Into::into).collect(),
            cmdline_paths: Vec::new(),
        })
    }

    /// Observe the installed native policy using captured, not current-executor,
    /// identity. This is coverage evidence only; it cannot authorize execution.
    pub(crate) fn installed_coverage(
        &self,
        engine: &crate::opa::OpaEngine,
        frozen: &FrozenRequest,
    ) -> Option<u64> {
        use crate::opa::{NetworkAction, NetworkInput};
        let endpoint = self.scope.endpoints.first()?;
        // Extraction narrows `ports` to the actual held destination; legacy
        // `port` may still describe the first port of the original endpoint.
        let [port] = endpoint.ports.as_slice() else {
            return None;
        };
        let port = u16::try_from(*port).ok()?;
        let authorization = engine
            .authorize_egress(&NetworkInput {
                host: endpoint.host.clone(),
                port,
                binary_path: self.binary.clone().into(),
                binary_sha256: String::new(),
                ancestors: self.ancestors.iter().map(Into::into).collect(),
                cmdline_paths: Vec::new(),
            })
            .ok()?;
        if !matches!(authorization.action, NetworkAction::Allow { .. })
            || !authorization.endpoint_configs.iter().any(|value| {
                super::parse_l7_config(value).is_some_and(|config| {
                    config.protocol == super::L7Protocol::Rest
                        && config.enforcement == super::EnforcementMode::Enforce
                })
            })
        {
            return None;
        }
        let tunnel = engine
            .clone_engine_for_tunnel(authorization.generation)
            .ok()?;
        let ctx = L7EvalContext {
            host: endpoint.host.clone(),
            port,
            workspace: self.workspace.clone(),
            request_default_port: None,
            policy_name: String::new(),
            binary_path: self.binary.clone(),
            ancestors: self.ancestors.clone(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
            provider_credentials: None,
            provider_credential_revision: None,
            provider_credential_installation_id: None,
            body_classifier: None,
            activity_tx: None,
            token_grant_resolver: None,
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            endpoint_observation_tx: None,
        };
        let request = frozen.request();
        let decision = super::hitl::evaluate_l7_request_classified(
            &tunnel,
            &ctx,
            &super::L7RequestInfo {
                action: request.action.clone(),
                target: request.target.clone(),
                query_params: request.query_params.clone(),
                graphql: None,
                jsonrpc: None,
            },
        )
        .ok()?;
        (decision.allowed
            && decision.l4_allowed
            && decision.binary_identity_required
            && !tunnel.is_stale())
        .then_some(authorization.generation)
    }

    #[must_use]
    pub fn scope(&self) -> &NetworkPolicyRule {
        &self.scope
    }
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn binary(&self) -> &str {
        &self.binary
    }
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// Stable review metadata, not authenticated gateway provenance and not a
    /// claim that a waiter is still alive. Per-waiter deadlines/IDs stay local.
    #[must_use]
    pub fn review_metadata(&self) -> String {
        serde_json::json!({
            "source": "held_http_request",
            "workspace": self.workspace,
            "binary": self.binary,
            "ancestors": self.ancestors,
            "source_policy": self.source_policy,
            "base_generation": self.generation,
            "base_policy_hash": self.policy_hash,
            "method": self.method,
            "normalized_path": self.path,
            "effect": "Persistent native REST rule; method matching is case-insensitive, GET includes HEAD. Query values are not constrained. Binary paths retain native executable-or-ancestor semantics. Request may have expired or disconnected; approval is not forwarding authority."
        }).to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalSubmitError {
    Retryable,
    Unavailable,
}

pub type ProposalSubmission<'a> =
    Pin<Box<dyn Future<Output = Result<String, ProposalSubmitError>> + Send + 'a>>;

/// Gateway ledger observation, not proof of installation or human attribution.
/// In particular, legacy/system rejection must not be described as a human act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewDecision {
    Unknown,
    Pending,
    Approved,
    Rejected,
}

pub type ProposalObservation<'a> =
    Pin<Box<dyn Future<Output = Result<ReviewDecision, ProposalSubmitError>> + Send + 'a>>;

/// Implemented by the supervisor composition layer, not by a workload API.
pub trait HeldProposalService: Send + Sync {
    fn submit<'a>(&'a self, input: &'a HeldProposalInput) -> ProposalSubmission<'a>;

    /// Implementations coalesce sandbox-wide reads; never mutate policy here.
    /// The default preserves submit-only adapters without inventing decisions.
    fn observe<'a>(&'a self, _workspace: &'a str, _chunk_id: &'a str) -> ProposalObservation<'a> {
        Box::pin(async { Ok(ReviewDecision::Unknown) })
    }
}

fn literal_binary(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path.len() <= 4096
        && !path
            .chars()
            .any(|c| c.is_control() || "*?[]{}\\".contains(c))
}

/// Native REST can express this literal subset without treating request data
/// as a glob. This does NOT change its GET/HEAD or case-folding semantics.
pub(crate) fn native_literal_request(method: &str, path: &str) -> bool {
    !method.is_empty()
        && method.len() <= 64
        && method.bytes().all(|b| b.is_ascii_alphabetic())
        && path.starts_with('/')
        && path.len() <= super::path::MAX_PATH_LEN
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
        && super::path::canonicalize_request_target(
            path,
            &super::path::CanonicalizeOptions::default(),
        )
        .is_ok_and(|(canonical, query)| canonical.path == path && query.is_none())
}

/// Extract only after classification has been bound to this exact frozen Q.
/// Fail closed rather than guess wildcard scopes, ambiguous route templates,
/// untrusted argv identities, or unsupported authored-policy projections.
pub(crate) fn extract(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    config: &L7EndpointConfig,
    frozen: &FrozenRequest,
) -> Option<HeldProposalInput> {
    engine.generation_guard().ensure_current().ok()?;
    let request = frozen.request();
    if ctx.workspace.is_empty()
        || ctx.policy_name.is_empty()
        || !literal_binary(&ctx.binary_path)
        || ctx.ancestors.len() > 128
        || ctx.ancestors.iter().any(|path| !literal_binary(path))
        || !native_literal_request(&request.action, &request.target)
    {
        return None;
    }
    // Validate parser projections against the canonical frozen header as
    // well. In particular, FORWARD must retain the original query in Q even
    // though none of its values belongs in the proposal or its fingerprint.
    let line = std::str::from_utf8(&request.raw_header)
        .ok()?
        .split("\r\n")
        .next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != request.action {
        return None;
    }
    let (canonical, query) = super::path::canonicalize_request_target(
        parts.next()?,
        &super::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        },
    )
    .ok()?;
    if canonical.path != request.target
        || query.as_deref().map_or_else(
            || Some(std::collections::HashMap::new()),
            |query| super::rest::parse_query_params(query).ok(),
        )? != request.query_params
    {
        return None;
    }
    let value = {
        let mut opa = engine.engine().lock().ok()?;
        // The classified evaluation left the original trusted exec/network
        // input installed; verify it selected the L4 owner carried by ctx.
        let matched = opa
            .eval_rule("data.openshell.sandbox.matched_network_policy".into())
            .ok()?;
        if serde_json::to_value(matched).ok()?.as_str()? != ctx.policy_name {
            return None;
        }
        serde_json::to_value(opa.get_data()).ok()?
    };
    let mut rule = value
        .get("network_policies")?
        .get(&ctx.policy_name)?
        .clone();
    let endpoints = rule.get_mut("endpoints")?.as_array_mut()?;
    for endpoint in endpoints.iter_mut() {
        let object = endpoint.as_object_mut()?;
        object.remove("policy_hash");
        object.remove("endpoint_id");
        // Informational proto-only marker, not an authorization constraint.
        object.remove("advisor_proposed");
    }
    let mut document = serde_json::json!({"version": 1, "network_policies": {}});
    document["network_policies"][&ctx.policy_name] = rule;
    let mut policy: SandboxPolicy =
        openshell_policy::parse_sandbox_policy(&document.to_string()).ok()?;
    let mut scope = policy.network_policies.remove(&ctx.policy_name)?;
    scope.binaries.retain(|binary| {
        literal_binary(&binary.path)
            && (binary.path == ctx.binary_path || ctx.ancestors.contains(&binary.path))
    });
    scope.binaries.sort_by(|a, b| a.path.cmp(&b.path));
    scope.binaries.dedup_by(|a, b| a.path == b.path);
    if scope.binaries.is_empty() {
        return None;
    }
    scope.endpoints.retain(|endpoint| {
        endpoint.host.eq_ignore_ascii_case(&ctx.host)
            && endpoint.protocol == "rest"
            && endpoint.path == config.path
            && endpoint.enforcement == openshell_core::proto::NetworkEnforcementMode::Enforce as i32
            && (if endpoint.ports.is_empty() {
                endpoint.port == u32::from(ctx.port)
            } else {
                endpoint.ports.contains(&u32::from(ctx.port))
            })
    });
    if scope.endpoints.len() != 1 {
        return None;
    }
    let endpoint = &mut scope.endpoints[0];
    // Narrow destination, port and allow-rule only. Preserve native deny,
    // TLS, allowed-IP and credential-binding constraints from the L4 owner.
    endpoint.host = ctx.host.to_ascii_lowercase();
    endpoint.port = u32::from(ctx.port);
    endpoint.ports = vec![u32::from(ctx.port)];
    endpoint.rules.clear();
    endpoint.access = 0;
    endpoint.advisor_proposed = true;
    engine.generation_guard().ensure_current().ok()?;
    Some(HeldProposalInput {
        scope,
        method: request.action.clone(),
        path: request.target.clone(),
        binary: ctx.binary_path.clone(),
        ancestors: ctx.ancestors.clone(),
        workspace: ctx.workspace.clone(),
        generation: engine.captured_generation(),
        policy_hash: config.policy_hash.clone(),
        source_policy: ctx.policy_name.clone(),
    })
}

#[cfg(test)]
mod tests;
