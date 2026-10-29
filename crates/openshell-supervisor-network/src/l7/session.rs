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
    /// Native processing owns the request; no review snapshot is retained.
    Exchanging,
    Terminal,
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
        self.state = CaptureState::PendingReview;
        // Admission was classified, but it conveys NO retained execution
        // authority. No policy/evaluator is needed by the waiting owner.
        self.invalidate_classification();
        ocsf_emit!(
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Informational)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .message("HTTP_HITL_WAIT admitted; release disabled")
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
        if !self.slot.is_waiting() {
            return None;
        }
        let waiter = self.slot.waiter.as_ref()?;
        let reason = waiter.wait(&mut self.client).await;
        let (host, port) = waiter.destination();
        ocsf_emit!(
            NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .severity(SeverityId::Informational)
                .dst_endpoint(Endpoint::from_domain(host, port))
                .message(format!("HTTP_HITL_WAIT terminal={reason:?}; no release"))
                .build()
        );
        self.slot.terminate();
        Some(reason)
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
