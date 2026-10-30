// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, cancellation-owned submission of pending human-review proposals.
//! Submission and coalesced read-only decision observation never authorize forwarding.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::Duration;

use openshell_core::grpc_client::CachedOpenShellClient;
use openshell_core::proposals::{HTTP_HITL_ANALYSIS_MODE, http_hitl_submission_fingerprint};
use openshell_core::proto::{
    GetDraftPolicyRequest, GetDraftPolicyResponse, PolicyChunk, SubmitPolicyAnalysisRequest,
    SubmitPolicyAnalysisResponse,
};
use openshell_supervisor_network::l7::proposal::{
    HeldProposalInput, HeldProposalService, ProposalObservation, ProposalSubmission,
    ProposalSubmitError, ReviewDecision,
};
use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, sleep_until, timeout};

const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_INTERVAL: Duration = Duration::from_secs(1);
const CACHE_CAPACITY: usize = 16;
// Bound the existing all-drafts RPC without adding a new public API. Oversized
// ledgers fail closed; never accept a truncated response as a complete snapshot.
const REVIEW_RESPONSE_BYTES: usize = 256 * 1024;
const REVIEW_CHUNKS: usize = 1024;

struct ReviewState {
    next_attempt: Instant,
    workspace: String,
    snapshot: Option<HashMap<String, ReviewDecision>>,
}

struct SubmissionState {
    next_attempt: Instant,
    accepted: VecDeque<(String, String)>,
}

pub struct ProposalService {
    endpoint: String,
    sandbox_name: String,
    workspace_rx: watch::Receiver<String>,
    session_id: uuid::Uuid,
    state: Mutex<SubmissionState>,
    review: Mutex<ReviewState>,
}

impl ProposalService {
    pub(crate) fn new(
        endpoint: String,
        sandbox_name: String,
        workspace_rx: watch::Receiver<String>,
    ) -> Self {
        Self {
            endpoint,
            sandbox_name,
            workspace_rx,
            session_id: uuid::Uuid::new_v4(),
            state: Mutex::new(SubmissionState {
                next_attempt: Instant::now(),
                accepted: VecDeque::with_capacity(CACHE_CAPACITY),
            }),
            review: Mutex::new(ReviewState {
                next_attempt: Instant::now(),
                workspace: String::new(),
                snapshot: None,
            }),
        }
    }

    fn check_workspace(&self, workspace: &str) -> Result<(), ProposalSubmitError> {
        if workspace.is_empty() || self.workspace_rx.borrow().as_str() != workspace {
            return Err(ProposalSubmitError::Unavailable);
        }
        Ok(())
    }

    // Cooperative coordinator: all active waiters share one bounded batch
    // snapshot and at most one read RPC per second. No task survives its owner.
    async fn observe_candidate<F, Fut>(
        &self,
        workspace: &str,
        chunk_id: &str,
        fetch: F,
    ) -> Result<ReviewDecision, ProposalSubmitError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<GetDraftPolicyResponse, ProposalSubmitError>>,
    {
        self.check_workspace(workspace)?;
        let mut state = self.review.lock().await;
        self.check_workspace(workspace)?;
        if state.workspace != workspace {
            state.snapshot = None;
            state.workspace = workspace.to_string();
        }
        if Instant::now() >= state.next_attempt {
            state.next_attempt = Instant::now() + ATTEMPT_INTERVAL;
            // Cancel/error cannot leave a previous approval looking current.
            state.snapshot = None;
            let response = timeout(RPC_TIMEOUT, fetch()).await;
            // Share even a slow fetch/error with queued waiters instead of
            // issuing one back-to-back RPC for each of them on completion.
            state.next_attempt = Instant::now() + ATTEMPT_INTERVAL;
            self.check_workspace(workspace)?;
            let response = response.map_err(|_| ProposalSubmitError::Retryable)??;
            if response.chunks.len() > REVIEW_CHUNKS {
                return Err(ProposalSubmitError::Unavailable);
            }
            let mut snapshot = HashMap::with_capacity(response.chunks.len());
            for chunk in response.chunks {
                let decision = match chunk.status.as_str() {
                    "pending" => ReviewDecision::Pending,
                    "approved" => ReviewDecision::Approved,
                    "rejected" => ReviewDecision::Rejected,
                    _ => ReviewDecision::Unknown,
                };
                if chunk.id.is_empty() || snapshot.insert(chunk.id, decision).is_some() {
                    return Err(ProposalSubmitError::Unavailable);
                }
            }
            state.snapshot = Some(snapshot);
        }
        self.check_workspace(workspace)?;
        Ok(state
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.get(chunk_id))
            .copied()
            .unwrap_or(ReviewDecision::Unknown))
    }

    // The injected operation keeps tests independent of the private network
    // input constructor. Production supplies only the existing gateway client.
    async fn submit_candidate<F, Fut>(
        &self,
        workspace: &str,
        mut chunk: PolicyChunk,
        submit: F,
    ) -> Result<String, ProposalSubmitError>
    where
        F: FnOnce(PolicyChunk) -> Fut,
        Fut: Future<Output = Result<SubmitPolicyAnalysisResponse, ProposalSubmitError>>,
    {
        self.check_workspace(workspace)?;
        let fingerprint = http_hitl_submission_fingerprint(&chunk);
        chunk.id = format!("{}:{fingerprint}", self.session_id);
        // One lock bounds memory and serializes every connect/sleep/RPC across
        // waiters. All work is owned by this future; dropping it cancels work.
        let mut state = self.state.lock().await;
        self.check_workspace(workspace)?;
        if let Some((_, id)) = state.accepted.iter().find(|(key, _)| key == &fingerprint) {
            self.check_workspace(workspace)?;
            return Ok(id.clone());
        }
        sleep_until(state.next_attempt).await;
        self.check_workspace(workspace)?;
        // Reserve before awaiting: cancellation or transport failure must not
        // allow a second waiter to bypass the global attempt rate limit.
        state.next_attempt = Instant::now() + ATTEMPT_INTERVAL;
        let result = timeout(RPC_TIMEOUT, submit(chunk)).await;
        self.check_workspace(workspace)?;
        let response = result.map_err(|_| ProposalSubmitError::Retryable)??;
        let id = accepted_id(response)?;
        if state.accepted.len() == CACHE_CAPACITY {
            state.accepted.pop_front();
        }
        state.accepted.push_back((fingerprint, id.clone()));
        self.check_workspace(workspace)?;
        Ok(id)
    }
}

impl HeldProposalService for ProposalService {
    fn observe<'a>(&'a self, workspace: &'a str, chunk_id: &'a str) -> ProposalObservation<'a> {
        Box::pin(
            self.observe_candidate(workspace, chunk_id, move || async move {
                let result = CachedOpenShellClient::connect(&self.endpoint).await;
                self.check_workspace(workspace)?;
                let client = result.map_err(classify_gateway_error)?;
                client.set_workspace(workspace.to_string());
                client
                    .raw_client()
                    .max_decoding_message_size(REVIEW_RESPONSE_BYTES)
                    .get_draft_policy(GetDraftPolicyRequest {
                        sandbox: self.sandbox_name.clone(),
                        workspace_scope: Some(openshell_core::proto::workspace_selector(workspace)),
                        status_filter: String::new(),
                    })
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|status| classify_status(status.code()))
            }),
        )
    }

    fn submit<'a>(&'a self, input: &'a HeldProposalInput) -> ProposalSubmission<'a> {
        Box::pin(async move {
            self.check_workspace(input.workspace())?;
            let chunk = crate::mechanistic_mapper::generate_held_proposal(input)
                .ok_or(ProposalSubmitError::Unavailable)?;
            self.submit_candidate(input.workspace(), chunk, |chunk| async move {
                let result = CachedOpenShellClient::connect(&self.endpoint).await;
                self.check_workspace(input.workspace())?;
                let client = result.map_err(classify_gateway_error)?;
                client.set_workspace(input.workspace().to_string());
                // Use the cached client's authenticated transport, retaining
                // typed Status: its convenience wrapper uses IntoDiagnostic,
                // which erases the wrapped tonic status and its code.
                client
                    .raw_client()
                    .submit_policy_analysis(SubmitPolicyAnalysisRequest {
                        name: self.sandbox_name.clone(),
                        summaries: Vec::new(),
                        proposed_chunks: vec![chunk],
                        network_activity_summaries: Vec::new(),
                        analysis_mode: HTTP_HITL_ANALYSIS_MODE.into(),
                        workspace_scope: Some(openshell_core::proto::workspace_selector(
                            client.workspace(),
                        )),
                    })
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|status| classify_status(status.code()))
            })
            .await
        })
    }
}

fn accepted_id(response: SubmitPolicyAnalysisResponse) -> Result<String, ProposalSubmitError> {
    if response.accepted_chunks != 1 || response.rejected_chunks != 0 {
        return Err(ProposalSubmitError::Unavailable);
    }
    let mut ids = response.accepted_chunk_ids.into_iter();
    match (ids.next(), ids.next()) {
        (Some(id), None) if !id.trim().is_empty() => Ok(id),
        _ => Err(ProposalSubmitError::Unavailable),
    }
}

fn classify_gateway_error(error: miette::Report) -> ProposalSubmitError {
    // Never log/display the report: gateway errors can echo sensitive paths.
    error
        .chain()
        .find_map(|source| source.downcast_ref::<tonic::Status>())
        .map_or(ProposalSubmitError::Retryable, |status| {
            classify_status(status.code())
        })
}

fn classify_status(code: tonic::Code) -> ProposalSubmitError {
    match code {
        tonic::Code::Cancelled
        | tonic::Code::Unknown
        | tonic::Code::DeadlineExceeded
        | tonic::Code::ResourceExhausted
        | tonic::Code::Aborted
        | tonic::Code::Internal
        | tonic::Code::Unavailable => ProposalSubmitError::Retryable,
        _ => ProposalSubmitError::Unavailable,
    }
}

#[cfg(test)]
mod tests;
