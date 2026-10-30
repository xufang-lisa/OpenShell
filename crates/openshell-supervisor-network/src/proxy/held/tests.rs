// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Direct application-I/O fence tests, not current-executor continuity proof.

use super::*;
use crate::l7::wait::{WaitEnd, WaitReservation, WaitRuntime};
use crate::test_support::policy_with_native_executable_paths;
use openshell_core::proposals::AgentProposals;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

const WORKSPACE: &str = "fixture-team";
const REQUEST: &[u8] = b"GET /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n";
const REGO: &str = include_str!("../../../data/sandbox-policy.rego");
const DATA: &str = r"
network_policies:
  fixture:
    endpoints:
      - host: example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: /allowed }
    binaries:
      - path: /usr/bin/curl
";

struct Fixture {
    environment: ResumeEnvironment,
    runtime: Arc<WaitRuntime>,
    // Keep the original reservation alive throughout the application exchange.
    reservation: WaitReservation,
    policy: PolicyGenerationGuard,
    lifetime: Arc<ResumeFence>,
    workspace: watch::Sender<String>,
}

impl Fixture {
    fn new(captured_at: Instant) -> Self {
        let engine = Arc::new(
            OpaEngine::from_strings(REGO, &policy_with_native_executable_paths(DATA)).unwrap(),
        );
        engine.attach_http_hitl_policy_observer();
        engine.set_http_hitl_wait_enabled(true);
        let runtime = engine.http_hitl_wait_runtime().clone();
        let reservation = runtime.reserve("example.com", 443, captured_at).unwrap();
        let policy = reservation
            .readmission_guard(engine.current_generation())
            .unwrap();
        let lifetime = reservation.resume_fence();
        let (workspace, workspace_rx) = watch::channel(WORKSPACE.to_owned());
        let environment = ResumeEnvironment {
            engine,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            backend_host_gateway: Arc::new(None),
            trusted_host_gateway: Arc::new(None),
            upstream_proxy: Arc::new(None),
            tls_state: None,
            policy_local_ctx: Some(Arc::new(PolicyLocalContext::new(
                None,
                None,
                None,
                AgentProposals::default(),
                workspace_rx,
            ))),
            // Credentials are deliberately not frozen into this fixture.
            provider_credentials: None,
            secret_resolver: None,
            agent_proposals: AgentProposals::default(),
            activity: None,
            endpoint_observation: None,
        };
        Self {
            environment,
            runtime,
            reservation,
            policy,
            lifetime,
            workspace,
        }
    }

    fn fence(&self, ready: Option<usize>) -> ApplicationFence<'_, Writer> {
        assert_eq!(self.runtime.population(), 1);
        assert_eq!(self.reservation.destination(), ("example.com", 443));
        ApplicationFence {
            inner: Writer {
                ready,
                ..Writer::default()
            },
            policy: &self.policy,
            lifetime: &self.lifetime,
            environment: &self.environment,
            workspace: WORKSPACE,
        }
    }

    fn reload(&self) {
        // Even reinstalling identical policy must invalidate the old guard.
        self.environment
            .engine
            .reload(REGO, &policy_with_native_executable_paths(DATA))
            .unwrap();
        assert!(self.policy.is_stale());
    }
}

/// A manually driven transport: Pending/zero/positive can change between polls.
/// No task, socket, timer, unsafe waker, or scheduling delay is needed.
#[derive(Default)]
struct Writer {
    ready: Option<usize>,
    write_polls: usize,
    bytes: Vec<u8>,
    flush_polls: usize,
    shutdown_polls: usize,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_polls += 1;
        let Some(count) = self.ready else {
            return Poll::Pending;
        };
        let count = count.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_polls += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown_polls += 1;
        Poll::Ready(Ok(()))
    }
}

fn write_once(fence: &mut ApplicationFence<'_, Writer>) -> Poll<io::Result<usize>> {
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    Pin::new(fence).poll_write(&mut cx, REQUEST)
}

fn assert_written(fence: &mut ApplicationFence<'_, Writer>, count: usize) {
    assert!(matches!(write_once(fence), Poll::Ready(Ok(n)) if n == count));
}

fn assert_error<T>(result: Poll<io::Result<T>>, expected: &str) {
    match result {
        Poll::Ready(Err(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(error.to_string(), expected);
        }
        _ => panic!("expected a ready fence error: {expected}"),
    }
}

fn assert_blocked(fence: &mut ApplicationFence<'_, Writer>, expected: &str) {
    let before = (
        fence.inner.write_polls,
        fence.inner.bytes.clone(),
        fence.inner.flush_polls,
        fence.inner.shutdown_polls,
    );
    // A formerly Pending socket is now writable. Re-polling must re-check the
    // fence rather than forwarding even the first byte to the inner writer.
    fence.inner.ready = Some(REQUEST.len());
    assert_error(write_once(fence), expected);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert_error(Pin::new(&mut *fence).poll_flush(&mut cx), expected);
    assert_error(Pin::new(&mut *fence).poll_shutdown(&mut cx), expected);
    assert_eq!(
        (
            fence.inner.write_polls,
            fence.inner.bytes.clone(),
            fence.inner.flush_polls,
            fence.inner.shutdown_polls,
        ),
        before,
        "no inner operation may run after a terminal fence check"
    );
}

#[tokio::test(start_paused = true)]
async fn pending_repoll_after_policy_reload_never_writes() {
    let fixture = Fixture::new(Instant::now());
    let mut fence = fixture.fence(None);
    assert!(write_once(&mut fence).is_pending());
    assert_eq!(fence.inner.write_polls, 1);
    fixture.reload();
    assert_blocked(&mut fence, "held policy stale");
    assert!(fence.inner.bytes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pending_repoll_after_disable_and_reenable_never_writes() {
    let fixture = Fixture::new(Instant::now());
    let mut fence = fixture.fence(None);
    assert!(write_once(&mut fence).is_pending());
    fixture.runtime.configure(false);
    fixture.runtime.configure(true);
    assert_eq!(fixture.lifetime.check(), Err(WaitEnd::Disabled));
    assert_blocked(&mut fence, "held lifetime ended");
    assert!(fence.inner.bytes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pending_repoll_beyond_original_capture_deadline_never_writes() {
    let captured_at = Instant::now();
    tokio::time::advance(Duration::from_secs(290)).await;
    let fixture = Fixture::new(captured_at);
    let mut fence = fixture.fence(None);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(write_once(&mut fence).is_pending());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(fixture.lifetime.check(), Err(WaitEnd::Deadline));
    assert_blocked(&mut fence, "held lifetime ended");
    assert!(fence.inner.bytes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn zero_writes_do_not_end_or_renew_original_capture_deadline() {
    let captured_at = Instant::now();
    tokio::time::advance(Duration::from_secs(290)).await;
    let fixture = Fixture::new(captured_at);
    let mut fence = fixture.fence(Some(0));
    assert_written(&mut fence, 0);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_written(&mut fence, 0);
    assert_eq!(fence.inner.write_polls, 2);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(fixture.lifetime.check(), Err(WaitEnd::Deadline));
    assert_blocked(&mut fence, "held lifetime ended");
    assert!(fence.inner.bytes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn first_positive_write_ends_capture_deadline_and_allows_flush_and_shutdown() {
    let fixture = Fixture::new(Instant::now());
    let mut fence = fixture.fence(None);
    assert!(write_once(&mut fence).is_pending());
    fence.inner.ready = Some(0);
    assert_written(&mut fence, 0);
    tokio::time::advance(Duration::from_secs(299)).await;
    fence.inner.ready = Some(1);
    assert_written(&mut fence, 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(fixture.lifetime.check(), Ok(()));
    assert_written(&mut fence, 1);
    assert_eq!(fence.inner.bytes, b"GG");
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut fence).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut fence).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(fence.inner.flush_polls, 1);
    assert_eq!(fence.inner.shutdown_polls, 1);
}

#[tokio::test(start_paused = true)]
async fn positive_write_does_not_disable_policy_reload_fence() {
    let fixture = Fixture::new(Instant::now());
    let mut fence = fixture.fence(Some(1));
    assert_written(&mut fence, 1);
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(fixture.lifetime.check(), Ok(()));
    fixture.reload();
    assert_blocked(&mut fence, "held policy stale");
    assert_eq!(fence.inner.bytes, b"G");
}

#[tokio::test(start_paused = true)]
async fn runtime_cancellation_blocks_pending_and_already_started_exchanges() {
    for started in [false, true] {
        for reason in [WaitEnd::Disabled, WaitEnd::Quarantined, WaitEnd::Shutdown] {
            let fixture = Fixture::new(Instant::now());
            let mut fence = fixture.fence(None);
            assert!(write_once(&mut fence).is_pending());
            if started {
                fence.inner.ready = Some(1);
                assert_written(&mut fence, 1);
                tokio::time::advance(Duration::from_secs(301)).await;
                assert_eq!(fixture.lifetime.check(), Ok(()));
            }
            match reason {
                WaitEnd::Disabled => fixture.runtime.configure(false),
                WaitEnd::Quarantined => fixture.runtime.quarantine(),
                WaitEnd::Shutdown => drop(fixture.runtime.shutdown_guard()),
                _ => unreachable!(),
            }
            assert_eq!(fixture.lifetime.check(), Err(reason));
            assert_blocked(&mut fence, "held lifetime ended");
            assert_eq!(fence.inner.bytes.len(), usize::from(started));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn workspace_change_blocks_pending_and_already_started_exchanges() {
    for started in [false, true] {
        let fixture = Fixture::new(Instant::now());
        let mut fence = fixture.fence(None);
        assert!(write_once(&mut fence).is_pending());
        if started {
            fence.inner.ready = Some(1);
            assert_written(&mut fence, 1);
        }
        fixture.workspace.send_replace("different-team".to_owned());
        assert_blocked(&mut fence, "held workspace changed");
        assert_eq!(fence.inner.bytes.len(), usize::from(started));
    }
}
