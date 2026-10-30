// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Preliminary REST human-review classification.
//!
//! There is deliberately no
//! request retention, proposal submission, credential resolution or upstream
//! write here. An eligible classification is NOT execution authority.

use super::provider::{BodyLength, L7Request};
use super::relay::L7EvalContext;
use super::{EnforcementMode, L7Decision, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::TunnelPolicyEngine;
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    ocsf_emit,
};
use serde::{Deserialize, Serialize};

/// Native decision classes, independent of human-readable diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum L7DecisionKind {
    Allowed,
    L4Denied,
    ExplicitDeny,
    ConstraintFailed,
    MissingRestAllow,
    OtherPolicyDeny,
    EvaluationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestHitlIneligibleReason {
    Disabled,
    EvaluationError,
    StalePolicy,
    UnsupportedProtocol,
    AuditMode,
    L4Denied,
    BinaryIdentityUnavailable,
    AlreadyAllowed,
    ExplicitDeny,
    ConstraintFailed,
    OtherPolicyDeny,
    UnsupportedHttpVersion,
    InvalidFraming,
    RequestBody,
    TransferEncoding,
    Expect,
    Upgrade,
    AuthorityMismatch,
    CredentialDependentTarget,
}

/// This preliminary result must never authorize a send. Later stages still
/// need an owned request slot, exact scope, quotas, approval, installed policy,
/// fresh executor admission and first-write fences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestHitlEligibility {
    EligibleForReview,
    Ineligible(RestHitlIneligibleReason),
}

// Required fields intentionally have no serde defaults: undefined, partial,
// malformed or unknown custom-policy outputs must never grant eligibility.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Atomic facts returned by native Rego authorization"
)]
struct RequestAuthorization {
    allowed: bool,
    l4_allowed: bool,
    binary_identity_required: bool,
    explicit_deny: bool,
    rest_endpoint: bool,
    rest_shape_matched: bool,
    reason: String,
}

pub(crate) fn evaluate_l7_request_classified(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<L7Decision> {
    engine.generation_guard().ensure_current()?;
    let result = {
        let mut opa = engine
            .engine()
            .lock()
            .map_err(|_| miette!("OPA engine lock poisoned"))?;
        crate::opa::set_regorus_input(
            &mut opa,
            super::relay::l7_request_policy_input(ctx, request),
        )?;
        let value = opa
            .eval_rule("data.openshell.sandbox.request_authorization".into())
            .map_err(|error| miette!("{error}"))?;
        serde_json::from_value::<RequestAuthorization>(
            serde_json::to_value(value).into_diagnostic()?,
        )
        .into_diagnostic()?
    };
    engine.generation_guard().ensure_current()?;
    let kind = if result.allowed {
        // A contradictory native result cannot create review authority.
        if result.explicit_deny || !result.l4_allowed {
            return Err(miette!("inconsistent L7 authorization result"));
        }
        L7DecisionKind::Allowed
    } else if !result.l4_allowed {
        L7DecisionKind::L4Denied
    } else if result.explicit_deny {
        L7DecisionKind::ExplicitDeny
    } else if result.rest_endpoint && result.rest_shape_matched {
        L7DecisionKind::ConstraintFailed
    } else if result.rest_endpoint {
        L7DecisionKind::MissingRestAllow
    } else {
        L7DecisionKind::OtherPolicyDeny
    };
    Ok(L7Decision {
        allowed: result.allowed,
        reason: result.reason,
        matched_rule: None,
        kind,
        l4_allowed: result.l4_allowed,
        binary_identity_required: result.binary_identity_required,
    })
}

fn supported_request_shape(
    request: &L7Request,
) -> std::result::Result<(), RestHitlIneligibleReason> {
    use RestHitlIneligibleReason as No;
    let Some(end) = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
    else {
        return Err(No::InvalidFraming);
    };
    if end != request.raw_header.len()
        || super::rest::validate_http_request_header_block(&request.raw_header).is_err()
    {
        // Never reinterpret read-ahead/body bytes as a bodyless request.
        return Err(No::InvalidFraming);
    }
    let header = std::str::from_utf8(&request.raw_header).map_err(|_| No::InvalidFraming)?;
    let mut lines = header.split("\r\n");
    let parts: Vec<_> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if parts.len() != 3 || parts[0] != request.action {
        return Err(No::InvalidFraming);
    }
    if parts[2] != "HTTP/1.1" {
        return Err(No::UnsupportedHttpVersion);
    }
    if request.action == "CONNECT" || request.action == "PRI" {
        return Err(No::UnsupportedProtocol);
    }
    let mut content_length_seen = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(No::InvalidFraming)?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if content_length_seen {
                    return Err(No::InvalidFraming);
                }
                content_length_seen = true;
            }
            "transfer-encoding" | "te" => return Err(No::TransferEncoding),
            "expect" => return Err(No::Expect),
            "upgrade" | "http2-settings" => return Err(No::Upgrade),
            "connection"
                if value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade")) =>
            {
                return Err(No::Upgrade);
            }
            _ => {}
        }
    }
    let framing = super::rest::parse_body_length(header).map_err(|_| No::InvalidFraming)?;
    if !matches!(framing, BodyLength::None | BodyLength::ContentLength(0))
        || !matches!(
            request.body_length,
            BodyLength::None | BodyLength::ContentLength(0)
        )
    {
        return Err(No::RequestBody);
    }
    Ok(())
}

pub(crate) fn assess_rest_hitl_candidate(
    enabled: bool,
    current: bool,
    config: &L7EndpointConfig,
    ctx: &L7EvalContext,
    request: &L7Request,
    decision: std::result::Result<&L7Decision, &miette::Report>,
) -> RestHitlEligibility {
    use RestHitlEligibility::{EligibleForReview, Ineligible};
    use RestHitlIneligibleReason as No;
    if !enabled {
        return Ineligible(No::Disabled);
    }
    if !current {
        return Ineligible(No::StalePolicy);
    }
    let Ok(decision) = decision else {
        return Ineligible(No::EvaluationError);
    };
    if config.protocol != L7Protocol::Rest {
        return Ineligible(No::UnsupportedProtocol);
    }
    if config.enforcement != EnforcementMode::Enforce {
        return Ineligible(No::AuditMode);
    }
    if !decision.l4_allowed {
        return Ineligible(No::L4Denied);
    }
    if !decision.binary_identity_required || ctx.binary_path.is_empty() {
        return Ineligible(No::BinaryIdentityUnavailable);
    }
    match decision.kind {
        L7DecisionKind::MissingRestAllow if !decision.allowed => {}
        L7DecisionKind::Allowed => return Ineligible(No::AlreadyAllowed),
        L7DecisionKind::ExplicitDeny => return Ineligible(No::ExplicitDeny),
        L7DecisionKind::ConstraintFailed => return Ineligible(No::ConstraintFailed),
        L7DecisionKind::L4Denied => return Ineligible(No::L4Denied),
        L7DecisionKind::EvaluationError => return Ineligible(No::EvaluationError),
        _ => return Ineligible(No::OtherPolicyDeny),
    }
    if let Err(reason) = supported_request_shape(request) {
        return Ineligible(reason);
    }
    // Both CONNECT/transparent relays and explicit FORWARD validate authority
    // before evaluation. Check again here so this helper cannot drift from it.
    if !super::relay::request_authority_matches_endpoint(request, ctx)
        || !matches!(
            super::rest::request_authority(&request.raw_header, ctx.request_default_port),
            Ok(Some(_))
        )
    {
        return Ineligible(No::AuthorityMismatch);
    }
    if !openshell_core::secrets::redact_target_for_policy(&request.target)
        .is_ok_and(|target| target == request.target)
    {
        return Ineligible(No::CredentialDependentTarget);
    }
    EligibleForReview
}

/// Shared HTTP seam for dedicated REST, route-selected HTTP and FORWARD. The
/// default-off path calls the native evaluator unchanged. Opt-in changes only
/// classification/observability; the caller retains its existing allow/deny.
#[cfg(test)]
pub(crate) fn evaluate_http_l7_request(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    config: &L7EndpointConfig,
    request: &L7Request,
    info: &L7RequestInfo,
) -> Result<(bool, String)> {
    evaluate_http_l7_request_observed(engine, ctx, config, request, info, None)
}

/// Bind observations to the outer-owned frozen request, never just a bool.
pub(crate) fn evaluate_http_l7_request_with_slot(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    config: &L7EndpointConfig,
    request: &L7Request,
    info: &L7RequestInfo,
    slot: &mut super::session::RequestSlot,
) -> Result<(bool, String)> {
    evaluate_http_l7_request_observed(engine, ctx, config, request, info, Some(slot))
}

fn evaluate_http_l7_request_observed(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    config: &L7EndpointConfig,
    request: &L7Request,
    info: &L7RequestInfo,
    mut slot: Option<&mut super::session::RequestSlot>,
) -> Result<(bool, String)> {
    if let Some(slot) = slot.as_deref_mut() {
        slot.invalidate_classification();
    }
    if config.protocol != L7Protocol::Rest || !engine.http_hitl_capture_enabled() {
        if let Some(slot) = slot {
            slot.release_snapshot();
        }
        return super::relay::evaluate_l7_request(engine, ctx, info);
    }
    // Classification must never replace native authorization, even when a
    // custom Rego policy exports a malformed or contradictory fact contract.
    let native = super::relay::evaluate_l7_request(engine, ctx, info);
    let result = evaluate_l7_request_classified(engine, ctx, info).and_then(|decision| {
        if !matches!(&native, Ok((allowed, _)) if *allowed == decision.allowed) {
            return Err(miette!(
                "classification disagrees with native authorization"
            ));
        }
        Ok(decision)
    });
    let mut eligibility = assess_rest_hitl_candidate(
        engine.http_hitl_capture_enabled(),
        !engine.is_stale(),
        config,
        ctx,
        request,
        result.as_ref(),
    );
    let kind = result
        .as_ref()
        .map_or(L7DecisionKind::EvaluationError, |d| d.kind);
    if slot.as_ref().is_some_and(|slot| {
        slot.frozen()
            .is_some_and(|frozen| frozen.buffered_after_header() != 0)
    }) && eligibility == RestHitlEligibility::EligibleForReview
    {
        eligibility = RestHitlEligibility::Ineligible(RestHitlIneligibleReason::InvalidFraming);
    }
    if let Some(slot) = slot {
        if eligibility == RestHitlEligibility::EligibleForReview
            && slot
                .record_classification(engine.generation_guard(), request, kind, eligibility)
                .is_err()
        {
            slot.invalidate_classification();
            eligibility =
                RestHitlEligibility::Ineligible(RestHitlIneligibleReason::EvaluationError);
        }
        if eligibility == RestHitlEligibility::EligibleForReview
            && let Some(input) = slot
                .frozen()
                .and_then(|frozen| super::proposal::extract(engine, ctx, config, frozen))
        {
            slot.set_proposal_input(input);
        }
        if eligibility != RestHitlEligibility::EligibleForReview {
            slot.release_snapshot();
        }
    }
    // This is a classification event, not an approval/application/execute event.
    let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(ActionId::Other)
        .disposition(DispositionId::Other)
        .severity(SeverityId::Informational)
        .http_request(HttpRequest::new(&info.action, ctx.ocsf_url(&info.target)))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, "l7-rest-classification")
        .unmapped("l7_decision_kind", serde_json::json!(kind))
        .unmapped("http_hitl_eligibility", serde_json::json!(eligibility))
        .message(format!(
            "HTTP_HITL_CLASSIFICATION kind={kind:?} eligibility={eligibility:?}"
        ))
        .build();
    ocsf_emit!(event);
    native
}

#[cfg(test)]
mod tests;
