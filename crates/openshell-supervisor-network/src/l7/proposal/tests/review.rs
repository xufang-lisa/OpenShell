// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::session::ReviewProgress;
use std::sync::Mutex;
use tokio::time::{Duration, advance};

struct Reviewer {
    decision: Mutex<ReviewDecision>,
    calls: AtomicUsize,
    mode: usize,
}

impl Reviewer {
    fn new(decision: ReviewDecision) -> Self {
        Self {
            decision: Mutex::new(decision),
            calls: AtomicUsize::new(0),
            mode: 0,
        }
    }
}

impl HeldProposalService for Reviewer {
    fn submit<'a>(&'a self, _: &'a HeldProposalInput) -> ProposalSubmission<'a> {
        Box::pin(async { Ok("shared-review".into()) })
    }

    fn observe<'a>(&'a self, workspace: &'a str, id: &'a str) -> ProposalObservation<'a> {
        Box::pin(async move {
            assert_eq!(workspace, "team");
            assert_eq!(id, "shared-review");
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                1 => std::future::pending().await,
                2 => Err(ProposalSubmitError::Retryable),
                3 => Err(ProposalSubmitError::Unavailable),
                _ => Ok(*self.decision.lock().unwrap()),
            }
        })
    }
}

fn held(
    engine: &Arc<OpaEngine>,
) -> (
    tokio::io::DuplexStream,
    HttpSession<tokio::io::DuplexStream>,
) {
    let tunnel = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    let mut slot = frozen_slot(&tunnel, &context(), "/missing");
    assert!(slot.try_begin_wait(&tunnel, "api.example.test", 80));
    let (client, transport) = tokio::io::duplex(8192);
    (
        client,
        HttpSession::from_reader(tokio::io::BufReader::new(transport), slot),
    )
}

async fn tick(session: &mut HttpSession<tokio::io::DuplexStream>) {
    let wait = session.wait_no_release();
    tokio::pin!(wait);
    assert!(poll!(wait.as_mut()).is_pending());
}

#[test]
fn http_hitl_coverage_uses_native_query_deny_ancestor_and_installed_generation() {
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let slot = frozen_slot(&tunnel, &context(), "/missing");
    let frozen = slot.frozen().unwrap();
    let input = extract(&tunnel, &context(), &config(), frozen).unwrap();
    assert_eq!(input.installed_coverage(&engine, frozen), None);

    let allowed = DATA.replace("path: /allowed", "path: /missing");
    engine.reload(POLICY, &allowed).unwrap();
    assert_eq!(input.installed_coverage(&engine, frozen), Some(1));
    for denied in [
        allowed.replace(
            "{method: DELETE, path: /blocked}",
            "{method: GET, path: /missing}",
        ),
        allowed.replace(
            "path: /missing}",
            "path: /missing, query: {mode: {glob: safe}}}",
        ),
        allowed.replace("/usr/bin/parent", "/usr/bin/not-parent"),
        allowed.replace("enforcement: enforce", "enforcement: audit"),
        allowed.replace("host: api.example.test", "host: elsewhere.example.test"),
        allowed.replace("ports: [80, 443]", "ports: [81, 443]"),
    ] {
        engine.reload(POLICY, &denied).unwrap();
        assert_eq!(input.installed_coverage(&engine, frozen), None);
    }
    engine.reload(POLICY, &allowed).unwrap();
    assert!(input.installed_coverage(&engine, frozen).is_some());
    engine.enter_fail_closed("fixture").unwrap();
    assert_eq!(input.installed_coverage(&engine, frozen), None);
}

#[test]
fn http_hitl_coverage_uses_actual_port_not_source_legacy_first_port() {
    let engine = OpaEngine::from_strings(POLICY, DATA).unwrap();
    engine.set_http_hitl_wait_enabled(true);
    let tunnel = engine.clone_engine_for_tunnel(0).unwrap();
    let ctx = L7EvalContext {
        port: 443,
        request_default_port: Some(443),
        ..context()
    };
    let slot = frozen_slot(&tunnel, &ctx, "/missing");
    let frozen = slot.frozen().unwrap();
    let mut input = extract(&tunnel, &ctx, &config(), frozen).unwrap();
    // Explicitly exercise compatibility data whose legacy port differs from
    // the extraction-narrowed authoritative destination.
    input.scope.endpoints[0].port = 80;
    let allowed = DATA.replace("path: /allowed", "path: /missing");
    engine
        .reload(POLICY, &allowed.replace("ports: [80, 443]", "ports: [443]"))
        .unwrap();
    assert!(input.installed_coverage(&engine, frozen).is_some());
    engine
        .reload(POLICY, &allowed.replace("ports: [80, 443]", "ports: [80]"))
        .unwrap();
    assert_eq!(input.installed_coverage(&engine, frozen), None);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_approved_then_covered_fails_closed_without_executor() {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
    engine.set_http_hitl_wait_enabled(true);
    engine.attach_http_hitl_policy_observer();
    let reviewer = Arc::new(Reviewer::new(ReviewDecision::Pending));
    engine.set_http_hitl_proposal_service(reviewer.clone());
    let (mut client, mut session) = held(&engine);
    tick(&mut session).await;
    assert_eq!(session.slot().review_progress(), ReviewProgress::Pending);
    *reviewer.decision.lock().unwrap() = ReviewDecision::Approved;
    advance(Duration::from_secs(1)).await;
    tick(&mut session).await;
    assert_eq!(
        session.slot().review_progress(),
        ReviewProgress::ApprovedAwaitingCoverage
    );
    // Unrelated reload is not coverage.
    engine.reload(POLICY, DATA).unwrap();
    tick(&mut session).await;
    assert_eq!(
        session.slot().review_progress(),
        ReviewProgress::ApprovedAwaitingCoverage
    );
    engine
        .reload(POLICY, &DATA.replace("path: /allowed", "path: /missing"))
        .unwrap();
    assert_eq!(
        session.wait_no_release().await,
        Some(WaitEnd::CurrentExecutorUnavailable)
    );
    assert_eq!(session.slot().state(), CaptureState::Terminal);
    assert!(session.slot().frozen().is_none());
    assert_eq!(session.slot().review_progress(), ReviewProgress::Unknown);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    // Neither policy changes nor late approval can revive the old request.
    engine.reload(POLICY, DATA).unwrap();
    engine
        .reload(POLICY, &DATA.replace("path: /allowed", "path: /missing"))
        .unwrap();
    advance(Duration::from_secs(299)).await;
    assert_eq!(session.wait_no_release().await, None);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    drop(session);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    let mut bytes = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client, &mut bytes)
        .await
        .unwrap();
    assert!(
        bytes.is_empty(),
        "unavailable executor never writes a response or upstream HTTP"
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_requires_approved_not_just_a_covering_reload() {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
    engine.set_http_hitl_wait_enabled(true);
    engine.attach_http_hitl_policy_observer();
    let reviewer = Arc::new(Reviewer::new(ReviewDecision::Pending));
    engine.set_http_hitl_proposal_service(reviewer.clone());
    let (_client, mut session) = held(&engine);
    tick(&mut session).await;
    engine
        .reload(POLICY, &DATA.replace("path: /allowed", "path: /missing"))
        .unwrap();
    tick(&mut session).await;
    assert_eq!(session.slot().review_progress(), ReviewProgress::Pending);
    *reviewer.decision.lock().unwrap() = ReviewDecision::Unknown;
    advance(Duration::from_secs(1)).await;
    tick(&mut session).await;
    assert_eq!(session.slot().review_progress(), ReviewProgress::Unknown);
    assert_eq!(session.slot().state(), CaptureState::PendingReview);
    *reviewer.decision.lock().unwrap() = ReviewDecision::Rejected;
    assert_eq!(
        session.wait_no_release().await,
        Some(WaitEnd::ProposalRejected)
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_without_coverage_preserves_original_deadline() {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
    engine.set_http_hitl_wait_enabled(true);
    engine.attach_http_hitl_policy_observer();
    engine.set_http_hitl_proposal_service(Arc::new(Reviewer::new(ReviewDecision::Approved)));
    let (_client, mut session) = held(&engine);
    tick(&mut session).await;
    advance(Duration::from_secs(299)).await;
    engine.reload(POLICY, DATA).unwrap();
    tick(&mut session).await;
    assert_eq!(
        session.slot().review_progress(),
        ReviewProgress::ApprovedAwaitingCoverage
    );
    advance(Duration::from_secs(1)).await;
    assert_eq!(session.wait_no_release().await, Some(WaitEnd::Deadline));
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    drop(session);
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_terminal_transport_or_deadline_wins_over_coverage() {
    for mode in 0..3 {
        let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
        engine.set_http_hitl_wait_enabled(true);
        engine.attach_http_hitl_policy_observer();
        let reviewer = Arc::new(Reviewer::new(ReviewDecision::Pending));
        engine.set_http_hitl_proposal_service(reviewer.clone());
        let (mut client, mut session) = held(&engine);
        tick(&mut session).await;
        *reviewer.decision.lock().unwrap() = ReviewDecision::Approved;
        engine
            .reload(POLICY, &DATA.replace("path: /allowed", "path: /missing"))
            .unwrap();
        let expected = match mode {
            0 => {
                client.shutdown().await.unwrap();
                WaitEnd::ClientClosed
            }
            1 => {
                client.write_all(b"extra").await.unwrap();
                WaitEnd::ExtraInput
            }
            _ => {
                advance(Duration::from_mins(5)).await;
                WaitEnd::Deadline
            }
        };
        assert_eq!(session.wait_no_release().await, Some(expected));
        assert_eq!(session.slot().state(), CaptureState::Terminal);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        drop(session);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn http_hitl_shared_rejection_terminates_waiters_but_disconnect_is_independent() {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
    engine.set_http_hitl_wait_enabled(true);
    engine.attach_http_hitl_policy_observer();
    let reviewer = Arc::new(Reviewer::new(ReviewDecision::Pending));
    engine.set_http_hitl_proposal_service(reviewer.clone());
    let (mut client_a, mut a) = held(&engine);
    let (_client_b, mut b) = held(&engine);
    let (_client_c, mut c) = held(&engine);
    tick(&mut a).await;
    tick(&mut b).await;
    tick(&mut c).await;
    client_a.shutdown().await.unwrap();
    assert_eq!(a.wait_no_release().await, Some(WaitEnd::ClientClosed));
    drop(a);
    assert_eq!(b.slot().state(), CaptureState::PendingReview);
    assert_eq!(*reviewer.decision.lock().unwrap(), ReviewDecision::Pending);
    *reviewer.decision.lock().unwrap() = ReviewDecision::Rejected;
    assert_eq!(b.wait_no_release().await, Some(WaitEnd::ProposalRejected));
    assert_eq!(c.wait_no_release().await, Some(WaitEnd::ProposalRejected));
    *reviewer.decision.lock().unwrap() = ReviewDecision::Approved;
    assert_eq!(
        b.wait_no_release().await,
        None,
        "late approve cannot resurrect a terminal waiter"
    );
    assert_eq!(engine.http_hitl_wait_runtime().population(), 2);
    drop((b, c));
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_review_unknown_retry_and_stall_keep_original_lifetime() {
    for mode in [0, 1, 2, 3] {
        let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
        engine.set_http_hitl_wait_enabled(true);
        let reviewer = Arc::new(Reviewer {
            mode,
            ..Reviewer::new(ReviewDecision::Unknown)
        });
        engine.set_http_hitl_proposal_service(reviewer.clone());
        let (_client, mut session) = held(&engine);
        if mode == 3 {
            assert_eq!(
                session.wait_no_release().await,
                Some(WaitEnd::ProposalUnavailable)
            );
        } else {
            tick(&mut session).await;
            advance(Duration::from_mins(5)).await;
            assert_eq!(session.wait_no_release().await, Some(WaitEnd::Deadline));
        }
        assert!(reviewer.calls.load(Ordering::SeqCst) >= 1);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
        drop(session);
        assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    }
}

#[tokio::test]
async fn http_hitl_stalled_review_cancels_on_disconnect_extra_input_and_disable() {
    for termination in 0..3 {
        let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
        engine.set_http_hitl_wait_enabled(true);
        engine.set_http_hitl_proposal_service(Arc::new(Reviewer {
            mode: 1,
            ..Reviewer::new(ReviewDecision::Unknown)
        }));
        let (mut client, mut session) = held(&engine);
        tick(&mut session).await;
        match termination {
            0 => client.shutdown().await.unwrap(),
            1 => client.write_all(b"extra").await.unwrap(),
            _ => engine.set_http_hitl_wait_enabled(false),
        }
        assert_eq!(
            session.wait_no_release().await,
            Some(match termination {
                0 => WaitEnd::ClientClosed,
                1 => WaitEnd::ExtraInput,
                _ => WaitEnd::Disabled,
            })
        );
    }
}
