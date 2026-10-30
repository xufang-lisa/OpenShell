// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Client-side ownership independent of a borrowed policy evaluation.
//!
//! These are capture primitives, not an approval queue or execution authority.
//! Keep the session outside any generation-local future. Never reconstruct a
//! TLS stream or discard its reader when that future is cancelled. Raw request
//! material is deliberately neither Debug nor Serialize.

use super::hitl::{L7DecisionKind, RestHitlEligibility};
use super::provider::L7Request;
use crate::opa::PolicyGenerationGuard;
use miette::{Result, miette};
use openshell_ocsf::{ActivityId, Endpoint, NetworkActivityBuilder, SeverityId, ocsf_emit};
use tokio::io::BufReader;
use tokio::time::Instant;

const READ_AHEAD_BYTES: usize = 8 * 1024;

/// Capture progress only; no state here means a request has been approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Capturing,
    Frozen,
    Classified,
    /// Bounded no-release wait; this is NOT evidence of a durable proposal.
    PendingReview,
    /// One frozen request has left review for fresh native admission. This is
    /// not a forwarding permit and cannot enter the review wait a second time.
    Readmitting,
    /// Native processing owns the request; no review snapshot is retained.
    Exchanging,
    Terminal,
}

/// Local observation only. Even coverage conveys no current-executor, route,
/// credential, middleware or first-write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewProgress {
    Unknown,
    Pending,
    ApprovedAwaitingCoverage,
    CoveredNoAuthority { generation: u64 },
}

/// Internal handoff only. Covered retains Q and its quota for fresh admission;
/// it provides neither full executor identity nor upstream write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewWaitOutcome {
    Terminal(super::wait::WaitEnd),
    Covered { generation: u64 },
}

/// Immutable local capture, including native parser canonicalization.
pub struct FrozenRequest {
    captured_header: Vec<u8>,
    request: L7Request,
    captured_at: Instant,
    buffered_after_header: usize,
}

impl FrozenRequest {
    /// Original bytes, before native request-target rewriting. Never log these.
    #[must_use]
    pub fn captured_header(&self) -> &[u8] {
        &self.captured_header
    }

    /// Native canonical request. Callers may clone it, not mutate the capture.
    #[must_use]
    pub fn request(&self) -> &L7Request {
        &self.request
    }

    /// Local monotonic freeze time; later policy generations must not reset it.
    #[must_use]
    pub fn captured_at(&self) -> Instant {
        self.captured_at
    }

    /// Capture-time evidence only; later input requires a lifetime watcher.
    #[must_use]
    pub fn buffered_after_header(&self) -> usize {
        self.buffered_after_header
    }
}

/// Generation-scoped observation, never a forwarding permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedClassification {
    pub generation: u64,
    pub kind: L7DecisionKind,
    pub eligibility: RestHitlEligibility,
}

/// A session-owned slot that exists before the first cancellable header read.
pub struct RequestSlot {
    state: CaptureState,
    partial_header: Vec<u8>,
    frozen: Option<FrozenRequest>,
    classification: Option<CapturedClassification>,
    classification_guard: Option<PolicyGenerationGuard>,
    capture_completed_at: Option<Instant>,
    wait_admission_enabled: bool,
    // Must outlive transport abort. Terminal clears Q, not this charge.
    waiter: Option<super::wait::WaitReservation>,
    proposal_input: Option<super::proposal::HeldProposalInput>,
    submitted_proposal: Option<String>,
    review_request_id: Option<String>,
    review_progress: ReviewProgress,
}

impl Default for RequestSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestSlot {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: CaptureState::Capturing,
            partial_header: Vec::new(),
            frozen: None,
            classification: None,
            classification_guard: None,
            capture_completed_at: None,
            wait_admission_enabled: false,
            waiter: None,
            proposal_input: None,
            submitted_proposal: None,
            review_request_id: None,
            review_progress: ReviewProgress::Unknown,
        }
    }

    #[must_use]
    pub fn state(&self) -> CaptureState {
        self.state
    }

    #[must_use]
    pub fn frozen(&self) -> Option<&FrozenRequest> {
        self.frozen.as_ref()
    }

    /// Accepted durable chunk associated with this individual waiter. It is
    /// not an approval, installation acknowledgment, or forwarding permit.
    #[must_use]
    pub fn submitted_proposal(&self) -> Option<&str> {
        self.submitted_proposal.as_deref()
    }

    /// Opaque per-waiter correlation, never part of shared proposal identity.
    #[must_use]
    pub fn review_request_id(&self) -> Option<&str> {
        self.review_request_id.as_deref()
    }

    /// Last observation, tagged with the installed generation when covered.
    /// Never consume this value as a send permit.
    #[must_use]
    pub fn review_progress(&self) -> ReviewProgress {
        self.review_progress
    }

    pub(crate) fn held_input(&self) -> Option<&super::proposal::HeldProposalInput> {
        self.proposal_input.as_ref()
    }

    pub(crate) fn set_proposal_input(&mut self, input: super::proposal::HeldProposalInput) {
        self.proposal_input = Some(input);
    }

    /// Includes bytes consumed before a cancelled parsing future. Never log it.
    #[must_use]
    pub fn partial_header(&self) -> &[u8] {
        &self.partial_header
    }

    pub(crate) fn capture_buffer(&mut self) -> Result<&mut Vec<u8>> {
        if self.state != CaptureState::Capturing {
            return Err(miette!("request slot is not capturing"));
        }
        Ok(&mut self.partial_header)
    }

    /// Move a complete proxy envelope to its outer dispatch owner. The owner
    /// keeps these wire bytes while FORWARD derives and freezes canonical Q.
    pub(crate) fn take_dispatch_header(&mut self) -> Result<Vec<u8>> {
        let buffer = self.capture_buffer()?;
        if !buffer.ends_with(b"\r\n\r\n") {
            return Err(miette!("proxy header capture is incomplete"));
        }
        let header = std::mem::take(buffer);
        self.capture_completed_at = Some(Instant::now());
        Ok(header)
    }

    /// Move the completed header to native processing without cloning it.
    /// There must be no await between this transfer and synchronous parsing.
    pub(crate) fn take_unretained_header(&mut self) -> Result<Vec<u8>> {
        self.capture_buffer()?;
        self.state = CaptureState::Exchanging;
        Ok(std::mem::take(&mut self.partial_header))
    }

    /// Classification ruled out review (or was disabled). Keep the original
    /// reader, but release all additional request/observation material now.
    pub(crate) fn release_snapshot(&mut self) {
        if matches!(self.state, CaptureState::Frozen | CaptureState::Classified) {
            self.invalidate_classification();
            self.frozen = None;
            self.state = CaptureState::Exchanging;
        }
    }

    pub(crate) fn freeze(
        &mut self,
        request: L7Request,
        buffered_after_header: usize,
    ) -> Result<()> {
        if self.state != CaptureState::Capturing {
            return Err(miette!("request slot cannot be frozen twice"));
        }
        self.frozen = Some(FrozenRequest {
            captured_header: std::mem::take(&mut self.partial_header),
            request,
            captured_at: self.capture_completed_at.unwrap_or_else(Instant::now),
            buffered_after_header,
        });
        self.state = CaptureState::Frozen;
        Ok(())
    }

    pub(crate) fn record_classification(
        &mut self,
        guard: &PolicyGenerationGuard,
        request: &L7Request,
        kind: L7DecisionKind,
        eligibility: RestHitlEligibility,
    ) -> Result<()> {
        self.invalidate_classification();
        guard.ensure_current()?;
        let frozen = self
            .frozen()
            .ok_or_else(|| miette!("classification requires a frozen request"))?;
        if !matches!(self.state, CaptureState::Frozen | CaptureState::Classified)
            || frozen.request.action != request.action
            || frozen.request.target != request.target
            || frozen.request.query_params != request.query_params
            || frozen.request.raw_header != request.raw_header
            || frozen.request.body_length != request.body_length
        {
            return Err(miette!("classification does not match the frozen request"));
        }
        self.classification = Some(CapturedClassification {
            generation: guard.captured_generation(),
            kind,
            eligibility,
        });
        self.classification_guard = Some(guard.clone());
        self.state = CaptureState::Classified;
        Ok(())
    }

    /// Stale observations cannot be used even if a caller missed invalidation.
    #[must_use]
    pub fn classification(&self, guard: &PolicyGenerationGuard) -> Option<CapturedClassification> {
        self.classification.filter(|value| {
            !guard.is_stale()
                && value.generation == guard.captured_generation()
                && self
                    .classification_guard
                    .as_ref()
                    .is_some_and(|captured| !captured.is_stale() && captured.same_snapshot(guard))
        })
    }

    /// Drop generation-local observation, retaining the exact original capture.
    pub fn invalidate_classification(&mut self) {
        self.classification = None;
        self.classification_guard = None;
        if self.state != CaptureState::PendingReview {
            self.proposal_input = None;
        }
        if self.state == CaptureState::Classified {
            self.state = CaptureState::Frozen;
        }
    }

    /// Only a production transport owner may opt into the pending-wait exit.
    /// Legacy borrowed L7 helpers keep their native deny behavior.
    pub(crate) fn enable_wait_admission(&mut self) {
        self.wait_admission_enabled = true;
    }

    pub(crate) fn is_waiting(&self) -> bool {
        self.state == CaptureState::PendingReview
    }

    pub(crate) fn resume_fence(&self) -> Option<std::sync::Arc<super::wait::ResumeFence>> {
        self.waiter
            .as_ref()
            .map(super::wait::WaitReservation::resume_fence)
    }

    /// Recheck at fresh admission; coverage is not a reusable execution grant.
    pub(crate) fn readmission_guard(
        &self,
        generation: u64,
    ) -> std::result::Result<PolicyGenerationGuard, super::wait::WaitEnd> {
        if self.state != CaptureState::Readmitting {
            return Err(super::wait::WaitEnd::PolicyChanged);
        }
        self.waiter
            .as_ref()
            .ok_or(super::wait::WaitEnd::PolicyChanged)?
            .readmission_guard(generation)
    }

    pub(crate) fn try_begin_wait(
        &mut self,
        engine: &crate::opa::TunnelPolicyEngine,
        host: &str,
        port: u16,
    ) -> bool {
        if !self.wait_admission_enabled
            || self.state != CaptureState::Classified
            || !self
                .classification(engine.generation_guard())
                .is_some_and(|value| value.eligibility == RestHitlEligibility::EligibleForReview)
        {
            return false;
        }
        let Some(frozen) = self.frozen.as_ref() else {
            return false;
        };
        if engine.http_hitl_wait_runtime().proposal_service().is_some()
            && self.proposal_input.is_none()
        {
            return false;
        }
        let Some(reservation) =
            engine
                .http_hitl_wait_runtime()
                .reserve(host, port, frozen.captured_at)
        else {
            return false;
        };
        if engine.is_stale() {
            return false;
        }
        self.waiter = Some(reservation);
        self.review_request_id = Some(uuid::Uuid::new_v4().to_string());
        self.state = CaptureState::PendingReview;
        // Admission was classified, but it conveys NO retained execution
        // authority. No policy/evaluator is needed by the waiting owner.
        self.invalidate_classification();
        ocsf_emit!(
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Informational)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .unmapped("request_id", serde_json::json!(self.review_request_id))
                .message("HTTP_HITL_WAIT admitted; awaiting review and fresh admission")
                .build()
        );
        true
    }

    /// Advance only after the native response completed and declared reusable.
    /// Never call this to recover from cancellation or a policy reload.
    pub(crate) fn complete_exchange(&mut self) -> Result<()> {
        if !matches!(
            self.state,
            CaptureState::Frozen | CaptureState::Classified | CaptureState::Exchanging
        ) {
            return Err(miette!("request slot has no completed exchange"));
        }
        let wait_admission_enabled = self.wait_admission_enabled;
        *self = Self::new();
        self.wait_admission_enabled = wait_admission_enabled;
        Ok(())
    }

    /// Absorbing terminal state. No subsequent parse or classification revives it.
    pub fn terminate(&mut self) {
        self.partial_header.clear();
        self.frozen = None;
        self.classification = None;
        self.classification_guard = None;
        self.proposal_input = None;
        self.review_progress = ReviewProgress::Unknown;
        self.state = CaptureState::Terminal;
    }
}

/// Original TCP/TLS object, reader and request slot outlive borrowed exchanges.
/// No evaluator, upstream socket, credential resolver or grant is stored here.
pub struct HttpSession<C> {
    // Rust drops fields in declaration order: definitive transport abort
    // MUST precede dropping the slot's quota reservation, including aborts.
    client: BufReader<C>,
    slot: RequestSlot,
}

impl<C: tokio::io::AsyncRead> HttpSession<C> {
    #[must_use]
    pub fn new(client: C) -> Self {
        Self::from_reader(
            BufReader::with_capacity(READ_AHEAD_BYTES, client),
            RequestSlot::new(),
        )
    }

    /// Move the SAME ingress reader, retaining all read-ahead. No `into_inner`.
    pub(crate) fn from_reader(client: BufReader<C>, slot: RequestSlot) -> Self {
        Self { client, slot }
    }

    /// No detached watcher tasks. The caller must own the transport and drop
    /// this session on return; shutdown/flush is not awaited without a bound.
    pub(crate) async fn wait_no_release(&mut self) -> Option<super::wait::WaitEnd>
    where
        C: Unpin,
    {
        match self.wait_for_review(false).await? {
            ReviewWaitOutcome::Terminal(reason) => Some(reason),
            ReviewWaitOutcome::Covered { .. } => unreachable!("legacy wait never resumes"),
        }
    }

    /// Limited MVP handoff using captured trusted connection identity for ONE
    /// frozen request. Current-executor lifecycle proof is explicitly deferred;
    /// callers must not invent a fresh/full identity from proposal metadata.
    pub(crate) async fn wait_for_approval(&mut self) -> Option<ReviewWaitOutcome>
    where
        C: Unpin,
    {
        self.wait_for_review(true).await
    }

    async fn wait_for_review(&mut self, allow_readmission: bool) -> Option<ReviewWaitOutcome>
    where
        C: Unpin,
    {
        if !self.slot.is_waiting() {
            return None;
        }
        let waiter = self.slot.waiter.as_ref()?;
        let outcome = 'waiting: {
            if self.slot.submitted_proposal.is_none()
                && let (Some(service), Some(input)) =
                    (waiter.proposal_service(), self.slot.proposal_input.as_ref())
            {
                let submission = async {
                    loop {
                        match service.submit(input).await {
                            Ok(chunk_id) if !chunk_id.is_empty() => break Some(chunk_id),
                            Ok(_) | Err(super::proposal::ProposalSubmitError::Unavailable) => {
                                break None;
                            }
                            Err(super::proposal::ProposalSubmitError::Retryable) => {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                };
                // Same original deadline, transport and terminal watchers during
                // connect, queued submission and retry. Never detach submission.
                tokio::select! {
                    biased;
                    reason = waiter.wait(&mut self.client) => {
                        break 'waiting ReviewWaitOutcome::Terminal(reason);
                    }
                    chunk_id = submission => {
                        self.slot.submitted_proposal = chunk_id;
                    }
                }
                if self.slot.submitted_proposal.is_none() {
                    break 'waiting ReviewWaitOutcome::Terminal(
                        super::wait::WaitEnd::ProposalUnavailable,
                    );
                }
                ocsf_emit!(
                    NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                        .activity(ActivityId::Other)
                        .severity(SeverityId::Informational)
                        .dst_endpoint(Endpoint::from_domain(
                            waiter.destination().0,
                            waiter.destination().1
                        ))
                        .unmapped("request_id", serde_json::json!(self.slot.review_request_id))
                        .unmapped("chunk_id", serde_json::json!(self.slot.submitted_proposal))
                        .message("HTTP_HITL_PROPOSAL accepted; awaiting review and fresh admission")
                        .build()
                );
            }
            if let (Some(service), Some(input), Some(chunk_id), Some(frozen)) = (
                waiter.proposal_service(),
                self.slot.proposal_input.as_ref(),
                self.slot.submitted_proposal.as_deref(),
                self.slot.frozen.as_ref(),
            ) {
                let progress = &mut self.slot.review_progress;
                let request_id = self.slot.review_request_id.as_deref();
                let observation = async {
                    loop {
                        use super::proposal::{ProposalSubmitError, ReviewDecision};
                        let guard = waiter.policy_guard();
                        let next = match service.observe(input.workspace(), chunk_id).await {
                            Ok(ReviewDecision::Rejected) => {
                                break ReviewWaitOutcome::Terminal(
                                    super::wait::WaitEnd::ProposalRejected,
                                );
                            }
                            Err(ProposalSubmitError::Unavailable) => {
                                break ReviewWaitOutcome::Terminal(
                                    super::wait::WaitEnd::ProposalUnavailable,
                                );
                            }
                            Ok(ReviewDecision::Approved) => waiter
                                .installed_coverage(input, frozen)
                                .map_or(ReviewProgress::ApprovedAwaitingCoverage, |generation| {
                                    ReviewProgress::CoveredNoAuthority { generation }
                                }),
                            Ok(ReviewDecision::Pending) => ReviewProgress::Pending,
                            Ok(ReviewDecision::Unknown) | Err(ProposalSubmitError::Retryable) => {
                                ReviewProgress::Unknown
                            }
                        };
                        if *progress != next {
                            *progress = next;
                            ocsf_emit!(
                                NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                                    .activity(ActivityId::Other)
                                    .severity(SeverityId::Informational)
                                    .dst_endpoint(Endpoint::from_domain(
                                        waiter.destination().0,
                                        waiter.destination().1
                                    ))
                                    .unmapped("request_id", serde_json::json!(request_id))
                                    .unmapped("chunk_id", serde_json::json!(chunk_id))
                                    .message(format!("HTTP_HITL_REVIEW state={next:?}; observation is not execution authority"))
                                    .build()
                            );
                        }
                        if let ReviewProgress::CoveredNoAuthority { generation } = next {
                            break if allow_readmission {
                                match waiter.readmission_guard(generation) {
                                    Ok(_) => ReviewWaitOutcome::Covered { generation },
                                    Err(reason) => ReviewWaitOutcome::Terminal(reason),
                                }
                            } else {
                                ReviewWaitOutcome::Terminal(waiter.readmission_end(generation))
                            };
                        }
                        // Configuration installation wakes coverage observation;
                        // timer fallback handles lost notices and ledger changes.
                        tokio::select! {
                            biased;
                            () = async {
                                if let Some(guard) = guard {
                                    guard.wait_until_stale().await;
                                } else {
                                    std::future::pending::<()>().await;
                                }
                            } => {}
                            () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                        }
                    }
                };
                tokio::select! {
                    biased;
                    reason = waiter.wait(&mut self.client) => ReviewWaitOutcome::Terminal(reason),
                    outcome = observation => outcome,
                }
            } else {
                ReviewWaitOutcome::Terminal(waiter.wait(&mut self.client).await)
            }
        };
        let ReviewWaitOutcome::Terminal(reason) = outcome else {
            // Do not clear Q, drop quota or leave another resumable waiter.
            self.slot.state = CaptureState::Readmitting;
            return Some(outcome);
        };
        let (host, port) = waiter.destination();
        ocsf_emit!(
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Informational)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .unmapped("request_id", serde_json::json!(self.slot.review_request_id))
                .unmapped("chunk_id", serde_json::json!(self.slot.submitted_proposal))
                .message(format!("HTTP_HITL_WAIT terminal={reason:?}; no release"))
                .build()
        );
        self.slot.terminate();
        Some(outcome)
    }

    /// Borrow without unwrapping the reader or replacing the client TLS object.
    pub fn parts(&mut self) -> (&mut BufReader<C>, &mut RequestSlot) {
        (&mut self.client, &mut self.slot)
    }

    #[must_use]
    pub fn slot(&self) -> &RequestSlot {
        &self.slot
    }

    /// Close the owned transport and discard capture only for a terminal event.
    /// A generation-local future being dropped must not call this method.
    pub async fn terminate(&mut self) -> std::io::Result<()>
    where
        C: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        self.slot.terminate();
        self.client.shutdown().await
    }
}

#[cfg(test)]
mod tests;
