// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Original-lifetime readmission/fence tests, not executor-lifecycle proof.

use super::*;
use crate::opa::OpaEngine;

const POLICY: &str = "package openshell.sandbox\ndefault allow := false\n";
const ORIGINAL_DATA: &str = "network_policies: {}\n";
const OTHER_DATA: &str = r"
network_policies:
  other:
    endpoints:
      - { host: other.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";

fn bound_runtime() -> (Arc<OpaEngine>, Arc<WaitRuntime>) {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, ORIGINAL_DATA).unwrap());
    engine.attach_http_hitl_policy_observer();
    engine.set_http_hitl_wait_enabled(true);
    let runtime = engine.http_hitl_wait_runtime().clone();
    (engine, runtime)
}

fn reserve(runtime: &Arc<WaitRuntime>) -> WaitReservation {
    runtime.reserve("example.com", 443, Instant::now()).unwrap()
}

fn assert_charged_until_drop(reservation: WaitReservation) {
    let runtime = reservation.runtime.clone();
    assert_eq!(runtime.population(), 1);
    assert_eq!(
        runtime
            .population
            .lock()
            .unwrap()
            .destinations
            .get(&reservation.key),
        Some(&1)
    );
    drop(reservation);
    assert_eq!(runtime.population(), 0);
    assert!(runtime.population.lock().unwrap().destinations.is_empty());
}

#[test]
fn http_hitl_readmission_current_generation_has_no_executor_authority() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    assert_eq!(
        reservation.readmission_end(generation + 1),
        WaitEnd::PolicyChanged
    );
    for _ in 0..2 {
        assert_eq!(
            reservation.readmission_end(generation),
            WaitEnd::CurrentExecutorUnavailable
        );
    }
    assert_charged_until_drop(reservation);
}

#[test]
fn http_hitl_readmission_stale_generation_including_reload_away_and_back() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let original_generation = engine.current_generation();

    engine.reload(POLICY, OTHER_DATA).unwrap();
    let other_generation = engine.current_generation();
    assert!(other_generation > original_generation);
    assert_eq!(
        reservation.readmission_end(original_generation),
        WaitEnd::PolicyChanged
    );
    assert_eq!(
        reservation.readmission_end(other_generation),
        WaitEnd::CurrentExecutorUnavailable
    );

    engine.reload(POLICY, ORIGINAL_DATA).unwrap();
    let restored_generation = engine.current_generation();
    assert!(restored_generation > other_generation);
    for stale_generation in [original_generation, other_generation] {
        assert_eq!(
            reservation.readmission_end(stale_generation),
            WaitEnd::PolicyChanged
        );
    }
    assert_eq!(
        reservation.readmission_end(restored_generation),
        WaitEnd::CurrentExecutorUnavailable
    );
    assert_charged_until_drop(reservation);
}

#[test]
fn http_hitl_readmission_dropped_weakly_bound_engine_is_policy_changed() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        reservation.readmission_end(generation),
        WaitEnd::PolicyChanged
    );
    assert_charged_until_drop(reservation);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_original_capture_deadline_is_not_renewed() {
    let (engine, runtime) = bound_runtime();
    let generation = engine.current_generation();
    let captured_at = Instant::now();
    tokio::time::advance(Duration::from_secs(290)).await;
    let reservation = runtime.reserve("example.com", 443, captured_at).unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(
        reservation.readmission_end(generation),
        WaitEnd::CurrentExecutorUnavailable
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Deadline);
    // Lifetime termination takes precedence even when policy observation is lost.
    drop(engine);
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Deadline);
    assert_charged_until_drop(reservation);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_disable_reenable_retains_disabled() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    runtime.configure(false);
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Disabled);
    runtime.configure(true);
    assert!(runtime.enabled());
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Disabled);
    drop(engine);
    tokio::time::advance(Duration::from_mins(5)).await;
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Disabled);
    assert_charged_until_drop(reservation);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_quarantine_recover_retains_quarantined() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    runtime.quarantine();
    assert_eq!(
        reservation.readmission_end(generation),
        WaitEnd::Quarantined
    );
    runtime.recover();
    assert!(!runtime.population.lock().unwrap().quarantined);
    assert_eq!(
        reservation.readmission_end(generation),
        WaitEnd::Quarantined
    );
    drop(engine);
    tokio::time::advance(Duration::from_mins(5)).await;
    assert_eq!(
        reservation.readmission_end(generation),
        WaitEnd::Quarantined
    );
    assert_charged_until_drop(reservation);
}

#[tokio::test(start_paused = true)]
async fn http_hitl_readmission_shutdown_retains_shutdown() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    drop(runtime.shutdown_guard());
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Shutdown);
    runtime.configure(true);
    runtime.recover();
    assert!(!runtime.enabled());
    assert!(
        runtime
            .reserve("other.example.com", 443, Instant::now())
            .is_none()
    );
    drop(engine);
    tokio::time::advance(Duration::from_mins(5)).await;
    assert_eq!(reservation.readmission_end(generation), WaitEnd::Shutdown);
    assert_charged_until_drop(reservation);
}

#[test]
fn http_hitl_readmission_terminal_result_does_not_release_either_quota() {
    let (engine, _) = bound_runtime();
    let runtime = Arc::new(WaitRuntime::with_limits(Duration::from_mins(5), 2, 1).unwrap());
    runtime.set_policy_engine(Arc::downgrade(&engine));
    runtime.configure(true);
    let reservation = reserve(&runtime);
    let other = runtime
        .reserve("other.example.com", 443, Instant::now())
        .unwrap();

    for expected in [WaitEnd::CurrentExecutorUnavailable, WaitEnd::PolicyChanged] {
        if expected == WaitEnd::PolicyChanged {
            engine.reload(POLICY, OTHER_DATA).unwrap();
        }
        assert_eq!(reservation.readmission_end(0), expected);
        assert_eq!(runtime.population(), 2);
        assert!(
            runtime
                .reserve("EXAMPLE.com.", 443, Instant::now())
                .is_none()
        );
        assert!(
            runtime
                .reserve("third.example.com", 443, Instant::now())
                .is_none()
        );
    }

    drop(other);
    assert_eq!(runtime.population(), 1);
    // With sandbox capacity available, the original destination is still charged.
    assert!(
        runtime
            .reserve("EXAMPLE.com.", 443, Instant::now())
            .is_none()
    );
    assert_charged_until_drop(reservation);
    let replacement = reserve(&runtime);
    let third = runtime
        .reserve("third.example.com", 443, Instant::now())
        .unwrap();
    assert_eq!(runtime.population(), 2);
    drop(third);
    assert_charged_until_drop(replacement);
}

#[test]
fn http_hitl_readmission_guard_accepts_only_current_generation_and_original_lifetime() {
    let (engine, runtime) = bound_runtime();
    let reservation = reserve(&runtime);
    let generation = engine.current_generation();
    let guard = reservation.readmission_guard(generation).unwrap();
    assert_eq!(guard.captured_generation(), generation);
    assert!(!guard.is_stale());
    assert!(matches!(
        reservation.readmission_guard(generation + 1),
        Err(WaitEnd::PolicyChanged)
    ));
    engine.reload(POLICY, OTHER_DATA).unwrap();
    assert!(guard.is_stale());
    assert!(matches!(
        reservation.readmission_guard(generation),
        Err(WaitEnd::PolicyChanged)
    ));
    let current = engine.current_generation();
    assert!(reservation.readmission_guard(current).is_ok());
    runtime.configure(false);
    runtime.configure(true);
    assert!(matches!(
        reservation.readmission_guard(current),
        Err(WaitEnd::Disabled)
    ));
    assert_charged_until_drop(reservation);
}

struct ApplicationWriter(Option<usize>);

impl tokio::io::AsyncWrite for ApplicationWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.map_or(std::task::Poll::Pending, |count| {
            std::task::Poll::Ready(Ok(count.min(bytes.len())))
        })
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// Models the caller's contract: check before EVERY poll, mark only a positive
// HTTP write. A pending socket/TLS poll is not permission to extend capture.
async fn application_write(
    fence: &ResumeFence,
    writer: &mut ApplicationWriter,
) -> Result<usize, WaitEnd> {
    std::future::poll_fn(|cx| {
        use tokio::io::AsyncWrite;
        fence.check()?;
        let result = std::pin::Pin::new(&mut *writer).poll_write(cx, b"GET / HTTP/1.1\r\n\r\n");
        if matches!(result, std::task::Poll::Ready(Ok(count)) if count > 0) {
            fence.mark_started();
        }
        result.map(|result| result.map_err(|_| WaitEnd::ClientError))
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn http_hitl_resume_fence_zero_and_pending_writes_keep_original_deadline() {
    use futures::poll;

    for ready in [Some(0), None] {
        let (engine, runtime) = bound_runtime();
        let captured = Instant::now();
        tokio::time::advance(Duration::from_secs(290)).await;
        let reservation = runtime.reserve("example.com", 443, captured).unwrap();
        let fence = reservation.resume_fence();
        let mut writer = ApplicationWriter(ready);
        let write = application_write(&fence, &mut writer);
        tokio::pin!(write);
        if ready.is_some() {
            assert_eq!(write.as_mut().await, Ok(0));
        } else {
            assert!(poll!(write.as_mut()).is_pending());
        }
        assert_eq!(fence.check(), Ok(()));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(fence.check(), Err(WaitEnd::Deadline));
        assert_eq!(fence.wait_cancelled().await, WaitEnd::Deadline);
        if ready.is_none() {
            assert_eq!(write.await, Err(WaitEnd::Deadline));
        }
        assert!(matches!(
            reservation.readmission_guard(engine.current_generation()),
            Err(WaitEnd::Deadline)
        ));
        assert_charged_until_drop(reservation);
    }
}

#[tokio::test(start_paused = true)]
async fn http_hitl_resume_fence_positive_write_ignores_deadline_not_runtime_cancellation() {
    use futures::poll;

    // Both notification orderings: subscriber already pending, or created only
    // after the first positive write. Transient runtime changes remain sticky.
    for subscribed_first in [false, true] {
        for cancellation in [WaitEnd::Disabled, WaitEnd::Quarantined, WaitEnd::Shutdown] {
            let (engine, runtime) = bound_runtime();
            let reservation = reserve(&runtime);
            let fence = reservation.resume_fence();
            let second_handle = reservation.resume_fence();
            assert!(Arc::ptr_eq(&fence, &second_handle));
            let cancelled = fence.wait_cancelled();
            tokio::pin!(cancelled);
            if subscribed_first {
                assert!(poll!(cancelled.as_mut()).is_pending());
            }
            assert_eq!(
                application_write(&second_handle, &mut ApplicationWriter(Some(1))).await,
                Ok(1)
            );
            tokio::time::advance(Duration::from_mins(5)).await;
            assert_eq!(fence.check(), Ok(()));
            assert!(poll!(cancelled.as_mut()).is_pending());
            // Readmission itself never renews the original lifetime, even if a
            // caller incorrectly attempts to re-enter after a successful write.
            assert!(matches!(
                reservation.readmission_guard(engine.current_generation()),
                Err(WaitEnd::Deadline)
            ));
            match cancellation {
                WaitEnd::Disabled => {
                    runtime.configure(false);
                    runtime.configure(true);
                }
                WaitEnd::Quarantined => {
                    runtime.quarantine();
                    runtime.recover();
                }
                WaitEnd::Shutdown => drop(runtime.shutdown_guard()),
                _ => unreachable!(),
            }
            assert_eq!(fence.check(), Err(cancellation));
            assert_eq!(cancelled.await, cancellation);
            assert_eq!(fence.wait_cancelled().await, cancellation);
            assert_charged_until_drop(reservation);
        }
    }
}

#[test]
fn http_hitl_resume_fence_neither_owns_nor_releases_capacity() {
    let runtime = Arc::new(WaitRuntime::with_limits(Duration::from_mins(5), 1, 1).unwrap());
    runtime.configure(true);
    let reservation = reserve(&runtime);
    let fence = reservation.resume_fence();
    drop(fence.clone());
    assert_eq!(runtime.population(), 1);
    assert!(
        runtime
            .reserve("example.com", 443, Instant::now())
            .is_none()
    );
    assert!(
        runtime
            .reserve("other.example.com", 443, Instant::now())
            .is_none()
    );
    // Even terminal cancellation leaves the session's charge intact.
    runtime.quarantine();
    assert_eq!(fence.check(), Err(WaitEnd::Quarantined));
    runtime.recover();
    assert_eq!(runtime.population(), 1);
    drop(reservation);
    assert_eq!(runtime.population(), 0);
    // Conversely, keeping a fence alive cannot retain a quota charge.
    let replacement = reserve(&runtime);
    drop(fence);
    assert_charged_until_drop(replacement);
}
