// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared state controlling agent-driven policy proposals.
//!
//! Initialised once during sandbox start from the `agent_policy_proposals_enabled`
//! setting and updated by the policy poll loop or authoritative supervisor
//! when the setting changes. Read by the `policy.local` route handler and by
//! the skills installer to gate the agent-controlled mutation surface.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::policy_identity::deterministic_policy_hash;
use crate::proto::{PolicyChunk, SandboxPolicy};
use sha2::{Digest, Sha256};

/// Submission mode for proposals requiring an explicit human decision.
pub const HTTP_HITL_ANALYSIS_MODE: &str = "http_hitl";
/// Rule namespace separating HTTP HITL proposals from endpoint observations.
pub const HTTP_HITL_RULE_PREFIX: &str = "http_hitl_";

/// Stable content identity for an HTTP HITL submission, not proof of provenance.
///
/// This is a non-security idempotency hash, like `deterministic_policy_hash`.
/// Only existing policy fields and submission metadata participate; observation
/// counters, timestamps, and the declared id do not affect a retry's identity.
#[must_use]
pub fn http_hitl_submission_fingerprint(chunk: &PolicyChunk) -> String {
    let mut policy = SandboxPolicy::default();
    if let Some(rule) = &chunk.proposed_rule {
        policy
            .network_policies
            .insert(chunk.rule_name.clone(), rule.clone());
    }
    let payload = serde_json::to_vec(&(
        deterministic_policy_hash(&policy),
        &chunk.rationale,
        &chunk.binary,
        &chunk.stage,
    ))
    .expect("serializing a tuple of strings cannot fail");
    format!("{:x}", Sha256::digest(payload))
}

/// Validate a session-scoped content id and return its durable dedup namespace.
///
/// The UUID is an isolation label supplied by the caller, not authenticated
/// supervisor identity, provenance, authority, or evidence of a live waiter.
#[must_use]
pub fn http_hitl_submission_key(chunk: &PolicyChunk) -> Option<String> {
    let (session, fingerprint) = chunk.id.split_once(':')?;
    if uuid::Uuid::parse_str(session).is_err()
        || fingerprint.len() != 64
        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !chunk.rule_name.starts_with(HTTP_HITL_RULE_PREFIX)
        || chunk.stage != "http-hitl"
        || fingerprint != http_hitl_submission_fingerprint(chunk)
    {
        return None;
    }
    Some(format!("http_hitl:{}", chunk.id))
}

/// Shared handle for the agent-driven policy proposal surface.
///
/// Clones point at the same atomic value, so the sandbox orchestrator can pass
/// this into the process and network supervisors and then update it from the
/// settings poll loop or supervisor control.
#[derive(Clone, Debug)]
pub struct AgentProposals {
    enabled: Arc<AtomicBool>,
}

impl AgentProposals {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(enabled)),
        }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn swap_enabled(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::Relaxed)
    }
}

impl Default for AgentProposals {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{L7Allow, L7QueryMatcher, L7Rule, NetworkEndpoint, NetworkPolicyRule};

    fn chunk() -> PolicyChunk {
        PolicyChunk {
            rule_name: "http_hitl_read".into(),
            proposed_rule: Some(NetworkPolicyRule {
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    rules: vec![L7Rule {
                        allow: Some(L7Allow {
                            method: "GET".into(),
                            path: "/items".into(),
                            ..Default::default()
                        }),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            rationale: "minimal metadata".into(),
            binary: "/usr/bin/curl".into(),
            stage: "http-hitl".into(),
            ..Default::default()
        }
    }

    #[test]
    fn http_hitl_fingerprint_is_deterministic_and_observation_independent() {
        let original = chunk();
        let fingerprint = http_hitl_submission_fingerprint(&original);
        assert_eq!(fingerprint.len(), 64);
        let mut retry = original.clone();
        retry.id = "ignored".into();
        retry.hit_count = 42;
        retry.confidence = 0.9;
        assert_eq!(fingerprint, http_hitl_submission_fingerprint(&retry));
        assert_eq!(fingerprint, http_hitl_submission_fingerprint(&original));
    }

    #[test]
    fn http_hitl_fingerprint_canonicalizes_existing_policy_maps() {
        let mut original = chunk();
        let allow = original.proposed_rule.as_mut().unwrap().endpoints[0].rules[0]
            .allow
            .as_mut()
            .unwrap();
        for key in ["b", "a", "c"] {
            allow.query.insert(
                key.into(),
                L7QueryMatcher {
                    glob: "public".into(),
                    ..Default::default()
                },
            );
        }
        let fingerprint = http_hitl_submission_fingerprint(&original);
        let mut reordered = original.clone();
        let allow = reordered.proposed_rule.as_mut().unwrap().endpoints[0].rules[0]
            .allow
            .as_mut()
            .unwrap();
        allow.query.clear();
        for key in ["c", "a", "b"] {
            allow.query.insert(
                key.into(),
                L7QueryMatcher {
                    glob: "public".into(),
                    ..Default::default()
                },
            );
        }
        assert_eq!(fingerprint, http_hitl_submission_fingerprint(&reordered));
        reordered.proposed_rule.as_mut().unwrap().endpoints[0].rules[0]
            .allow
            .as_mut()
            .unwrap()
            .query
            .get_mut("a")
            .unwrap()
            .glob = "different".into();
        assert_ne!(fingerprint, http_hitl_submission_fingerprint(&reordered));
    }

    #[test]
    fn http_hitl_key_rejects_altered_content_and_invalid_envelopes() {
        let mut original = chunk();
        original.id = format!(
            "{}:{}",
            uuid::Uuid::new_v4(),
            http_hitl_submission_fingerprint(&original)
        );
        assert_eq!(
            http_hitl_submission_key(&original),
            Some(format!("http_hitl:{}", original.id))
        );
        for field in 0..8 {
            let mut altered = original.clone();
            match field {
                0 => altered.rationale.push('!'),
                1 => altered.binary.push('!'),
                2 => altered.stage = "other".into(),
                3 => altered.rule_name = "ordinary".into(),
                4 => altered.proposed_rule.as_mut().unwrap().endpoints[0].port = 80,
                5 => altered.id = format!("not-a-uuid:{}", &original.id[37..]),
                6 => {
                    altered.id.pop();
                }
                _ => altered.proposed_rule = None,
            }
            assert!(
                http_hitl_submission_key(&altered).is_none(),
                "field {field}"
            );
        }
        let mut other_session = original.clone();
        other_session.id = format!("{}:{}", uuid::Uuid::new_v4(), &original.id[37..]);
        assert_ne!(
            http_hitl_submission_key(&original),
            http_hitl_submission_key(&other_session)
        );
    }
}
