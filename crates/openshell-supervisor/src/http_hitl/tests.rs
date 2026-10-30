// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::NetworkPolicyRule;
use std::sync::atomic::{AtomicUsize, Ordering};

mod review;

fn service() -> (watch::Sender<String>, ProposalService) {
    let (tx, rx) = watch::channel("workspace-a".to_string());
    (
        tx,
        ProposalService::new("unused".into(), "sandbox".into(), rx),
    )
}

fn candidate(workspace: &str, path: &str) -> PolicyChunk {
    PolicyChunk {
        rule_name: "http_hitl_test".into(),
        proposed_rule: Some(NetworkPolicyRule {
            name: "http_hitl_test".into(),
            ..Default::default()
        }),
        rationale: format!("workspace={workspace};path={path}"),
        stage: "http-hitl".into(),
        binary: "/usr/bin/curl".into(),
        ..Default::default()
    }
}

fn accepted(id: &str) -> SubmitPolicyAnalysisResponse {
    SubmitPolicyAnalysisResponse {
        accepted_chunks: 1,
        accepted_chunk_ids: vec![id.into()],
        ..Default::default()
    }
}

#[test]
fn http_hitl_response_requires_exactly_one_accepted_id() {
    assert_eq!(accepted_id(accepted("durable-id")), Ok("durable-id".into()));
    let invalid = [
        SubmitPolicyAnalysisResponse::default(),
        SubmitPolicyAnalysisResponse {
            rejected_chunks: 1,
            ..accepted("id")
        },
        SubmitPolicyAnalysisResponse {
            accepted_chunks: 2,
            ..accepted("id")
        },
        SubmitPolicyAnalysisResponse {
            accepted_chunk_ids: vec![],
            ..accepted("id")
        },
        SubmitPolicyAnalysisResponse {
            accepted_chunk_ids: vec!["a".into(), "b".into()],
            ..accepted("id")
        },
        accepted(""),
        accepted("  "),
    ];
    for response in invalid {
        assert_eq!(accepted_id(response), Err(ProposalSubmitError::Unavailable));
    }
}

#[test]
fn http_hitl_gateway_status_classification_preserves_tonic_codes() {
    for code in [
        tonic::Code::InvalidArgument,
        tonic::Code::PermissionDenied,
        tonic::Code::NotFound,
        tonic::Code::Unauthenticated,
        tonic::Code::FailedPrecondition,
        tonic::Code::Unimplemented,
    ] {
        let report = openshell_core::grpc_client::grpc_status_error(tonic::Status::new(
            code,
            "never displayed",
        ));
        assert_eq!(
            classify_gateway_error(report),
            ProposalSubmitError::Unavailable
        );
    }
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::Unknown,
    ] {
        assert_eq!(classify_status(code), ProposalSubmitError::Retryable);
    }
    assert_eq!(
        classify_gateway_error(miette::miette!("transport")),
        ProposalSubmitError::Retryable
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_cache_shares_equivalent_waiters_and_rechecks_workspace() {
    let (tx, service) = service();
    let chunk = candidate("workspace-a", "/items/42");
    let id = service
        .submit_candidate("workspace-a", chunk.clone(), |submitted| async move {
            assert!(openshell_core::proposals::http_hitl_submission_key(&submitted).is_some());
            Ok(accepted("durable-id"))
        })
        .await
        .unwrap();
    assert_eq!(id, "durable-id");
    assert_eq!(
        service
            .submit_candidate("workspace-a", chunk.clone(), |_| async {
                panic!("cache miss")
            })
            .await
            .unwrap(),
        id
    );
    tx.send_replace("workspace-b".into());
    assert_eq!(
        service
            .submit_candidate("workspace-a", chunk, |_| async {
                panic!("stale workspace")
            })
            .await,
        Err(ProposalSubmitError::Unavailable)
    );
    assert_eq!(
        service
            .submit_candidate("", candidate("", "/"), |_| async {
                panic!("empty workspace")
            })
            .await,
        Err(ProposalSubmitError::Unavailable)
    );
}

#[tokio::test(start_paused = true)]
async fn http_hitl_concurrent_equivalent_waiters_share_one_gateway_call() {
    let (_tx, service) = service();
    let calls = AtomicUsize::new(0);
    let submit = |chunk| {
        service.submit_candidate("workspace-a", chunk, |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(accepted("shared-id"))
        })
    };
    let (a, b) = tokio::join!(
        submit(candidate("workspace-a", "/")),
        submit(candidate("workspace-a", "/"))
    );
    assert_eq!(a.unwrap(), "shared-id");
    assert_eq!(b.unwrap(), "shared-id");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_retries_have_stable_session_content_ids_and_are_rate_limited() {
    let (_tx, service) = service();
    let chunk = candidate("workspace-a", "/items/42");
    let expected = format!(
        "{}:{}",
        service.session_id,
        http_hitl_submission_fingerprint(&chunk)
    );
    let start = Instant::now();
    for attempt in 0..3 {
        let expected = expected.clone();
        assert_eq!(
            service
                .submit_candidate("workspace-a", chunk.clone(), |submitted| async move {
                    assert_eq!(submitted.id, expected);
                    assert!(Instant::now() >= start + ATTEMPT_INTERVAL * attempt);
                    Err(ProposalSubmitError::Retryable)
                })
                .await,
            Err(ProposalSubmitError::Retryable)
        );
    }
    let (_other_tx, other) = self::service();
    assert_ne!(other.session_id, service.session_id);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_rpc_timeout_is_bounded_and_retryable() {
    let (_tx, service) = service();
    let start = Instant::now();
    let result = service
        .submit_candidate("workspace-a", candidate("workspace-a", "/"), |_| {
            std::future::pending()
        })
        .await;
    assert_eq!(result, Err(ProposalSubmitError::Retryable));
    assert_eq!(Instant::now() - start, RPC_TIMEOUT);
    assert!(service.state.lock().await.accepted.is_empty());
}

#[tokio::test(start_paused = true)]
async fn http_hitl_workspace_is_rechecked_after_rpc_and_before_cache_insert() {
    let (tx, service) = service();
    let result = service
        .submit_candidate("workspace-a", candidate("workspace-a", "/"), |_| async {
            tx.send_replace("workspace-b".into());
            tokio::task::yield_now().await;
            Ok(accepted("stale-id"))
        })
        .await;
    assert_eq!(result, Err(ProposalSubmitError::Unavailable));
    assert!(service.state.lock().await.accepted.is_empty());
}

#[tokio::test(start_paused = true)]
async fn http_hitl_workspace_is_rechecked_after_rate_limit_sleep() {
    let (tx, service) = service();
    service.state.lock().await.next_attempt = Instant::now() + ATTEMPT_INTERVAL;
    let submit =
        service.submit_candidate("workspace-a", candidate("workspace-a", "/"), |_| async {
            panic!("stale workspace")
        });
    let change = async {
        tokio::task::yield_now().await;
        tx.send_replace("workspace-b".into());
    };
    let (result, ()) = tokio::join!(submit, change);
    assert_eq!(result, Err(ProposalSubmitError::Unavailable));
}

#[tokio::test(start_paused = true)]
async fn http_hitl_workspace_is_rechecked_after_lock_wait() {
    let (tx, service) = service();
    let lock = service.state.lock().await;
    let submit =
        service.submit_candidate("workspace-a", candidate("workspace-a", "/"), |_| async {
            panic!("stale workspace")
        });
    let change = async {
        tokio::task::yield_now().await;
        tx.send_replace("workspace-b".into());
        drop(lock);
    };
    let (result, ()) = tokio::join!(submit, change);
    assert_eq!(result, Err(ProposalSubmitError::Unavailable));
}

#[tokio::test(start_paused = true)]
async fn http_hitl_cancellation_drops_rpc_and_unlocks_without_spawning() {
    let (_tx, service) = service();
    let calls = AtomicUsize::new(0);
    let submit =
        service.submit_candidate("workspace-a", candidate("workspace-a", "/"), |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        });
    assert!(timeout(Duration::from_millis(100), submit).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let state = service
        .state
        .try_lock()
        .expect("cancellation released mutex");
    assert!(state.accepted.is_empty());
    assert!(state.next_attempt > Instant::now());
}

#[tokio::test(start_paused = true)]
async fn http_hitl_cache_is_bounded_and_eviction_reuses_durable_submission_id() {
    let (_tx, service) = service();
    let original = candidate("workspace-a", "/0");
    let expected = format!(
        "{}:{}",
        service.session_id,
        http_hitl_submission_fingerprint(&original)
    );
    for index in 0..=CACHE_CAPACITY {
        service
            .submit_candidate(
                "workspace-a",
                candidate("workspace-a", &format!("/{index}")),
                |_| async { Ok(accepted("id")) },
            )
            .await
            .unwrap();
    }
    assert_eq!(service.state.lock().await.accepted.len(), CACHE_CAPACITY);
    service
        .submit_candidate("workspace-a", original, |submitted| async move {
            assert_eq!(submitted.id, expected);
            Ok(accepted("original-durable-id"))
        })
        .await
        .unwrap();
}

#[test]
fn http_hitl_workspace_metadata_changes_submission_fingerprint() {
    let a = candidate("workspace-a", "/items/42");
    let b = candidate("workspace-b", "/items/42");
    assert_ne!(
        http_hitl_submission_fingerprint(&a),
        http_hitl_submission_fingerprint(&b)
    );
}
