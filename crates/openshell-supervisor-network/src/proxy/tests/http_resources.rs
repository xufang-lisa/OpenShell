// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Independent task/FD census of the production direct-listener proxy in an
//! isolated current-thread runtime. Reviewer/identity are trusted test doubles,
//! not live Gateway approval or the native mediation-source accept lane.
//! Run alone with --test-threads=1: /proc/self/fd covers this entire process.

use super::*;
use futures::poll;
use tokio::sync::Notify;

const REGO: &str = include_str!("../../../data/sandbox-policy.rego");
const BURST: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Census {
    pub(super) tasks: usize,
    pub(super) fds: usize,
    pub(super) sockets: usize,
}

pub(super) fn census() -> Census {
    // The directory iterator temporarily owns an FD in EVERY snapshot. Do not
    // substitute FDSize (table capacity) or OS Threads for these counts.
    // Some transient files may disappear while we enumerate /proc/self/fd,
    // especially under a busy current-thread test runtime; skip these stale
    // observations rather than treating them as a leak or a hard failure.
    let mut fds = 0;
    let mut sockets = 0;
    for entry in std::fs::read_dir("/proc/self/fd").expect("own process FD census") {
        let Ok(entry) = entry else {
            continue;
        };
        fds += 1;
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        sockets += usize::from(target.to_string_lossy().starts_with("socket:["));
    }
    Census {
        tasks: tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        fds,
        sockets,
    }
}

#[derive(Default)]
struct ResourceReviewer {
    decision: AtomicU32,
    submitted: AtomicU32,
    unavailable: std::sync::atomic::AtomicBool,
    observed: Notify,
}

impl crate::l7::proposal::HeldProposalService for ResourceReviewer {
    fn submit<'a>(
        &'a self,
        _: &'a crate::l7::proposal::HeldProposalInput,
    ) -> crate::l7::proposal::ProposalSubmission<'a> {
        Box::pin(async move {
            let id = self.submitted.fetch_add(1, Ordering::AcqRel);
            Ok(format!("resource-fixture-{id}"))
        })
    }

    fn observe<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> crate::l7::proposal::ProposalObservation<'a> {
        Box::pin(async move {
            use crate::l7::proposal::ReviewDecision;
            if self.unavailable.load(Ordering::Acquire) {
                self.observed.notify_one();
                return Err(crate::l7::proposal::ProposalSubmitError::Unavailable);
            }
            match self.decision.load(Ordering::Acquire) {
                0 => {
                    self.observed.notify_one();
                    Ok(ReviewDecision::Pending)
                }
                1 => Ok(ReviewDecision::Approved),
                2 => Ok(ReviewDecision::Rejected),
                _ => unreachable!(),
            }
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum End {
    Response,
    Rejected,
    ClientClosed,
    Disabled,
    Deadline,
    ProxyShutdown,
    ReviewUnavailable,
}

async fn cycle(end: End, round: usize) {
    // Pin the authorized address for operator runs. Other CI hosts may use
    // their own local interface; bind fails rather than contacting a remote IP.
    let ip: Ipv4Addr = std::env::var("OPENSHELL_HTTP_RESOURCE_TEST_IP").map_or_else(
        |_| non_loopback_test_ipv4().expect("resource fixture needs a local IPv4 interface"),
        |ip| ip.parse().expect("resource test IPv4 override"),
    );
    assert!(!ip.is_loopback() && !ip.is_unspecified());
    let upstream = TcpListener::bind((ip, 0)).await.unwrap();
    let destination = upstream.local_addr().unwrap();
    let data = policy_with_native_executable_paths(&format!(
        "network_policies:\n  fixture:\n    endpoints:\n      - host: \"{ip}\"\n        port: {}\n        protocol: rest\n        enforcement: enforce\n        allowed_ips: [\"{ip}/32\"]\n        rules:\n          - allow: {{method: GET, path: /allowed}}\n    binaries:\n      - path: /usr/bin/curl\n",
        destination.port(),
    ));
    let covered = data.replace("path: /allowed", "path: /missing");
    let engine = Arc::new(native_identity_engine(REGO, &data).unwrap());
    engine.attach_http_hitl_policy_observer();
    engine.set_http_hitl_wait_enabled(true);
    let reviewer = Arc::new(ResourceReviewer::default());
    engine.set_http_hitl_proposal_service(reviewer.clone());
    let (_ready, ready) = tokio::sync::watch::channel(true);
    let mut proxy = Some(
        ProxyHandle::start_with_bind_addr(
            &ProxyPolicy { http_addr: None },
            Some(([127, 0, 0, 1], 0).into()),
            engine.clone(),
            Arc::new(BinaryIdentityCache::new()),
            Arc::new(AtomicU32::new(0)),
            None,
            None,
            Some(http_wait::held_proposal_context()),
            None,
            None,
            None,
            ready,
            &upstream_proxy::UpstreamProxyArgs::default(),
            None,
            None,
            None,
            Some(http_wait::held_test_identity()),
            None,
        )
        .await
        .unwrap(),
    );
    let address = proxy.as_ref().unwrap().http_addr().unwrap();
    let mut exit = Some(proxy.as_mut().unwrap().take_exit_receiver().unwrap());
    // One scheduling checkpoint starts the accept task, no census polling.
    tokio::task::yield_now().await;
    let baseline = census();
    assert_eq!(baseline.tasks, 1, "only the production accept loop");
    let mut clients = Vec::new();
    for index in 0..BURST {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(format!("GET http://{destination}/missing?round={round}&client={index} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes()).await.unwrap();
        reviewer.observed.notified().await;
        clients.push(client);
        assert_eq!(engine.http_hitl_wait_runtime().population(), clients.len());
    }
    let held = census();
    assert!(
        held.tasks >= baseline.tasks + BURST,
        "actual detached handlers, not held-owner inference"
    );
    assert!(
        poll!(Box::pin(upstream.accept()).as_mut()).is_pending(),
        "Pending must never dial"
    );
    assert_eq!(
        reviewer.submitted.load(Ordering::Acquire),
        u32::try_from(BURST).unwrap()
    );

    let shutdown = matches!(end, End::ProxyShutdown);
    let paused = matches!(end, End::Deadline);
    match end {
        End::Response => {
            reviewer.decision.store(1, Ordering::Release);
            engine.reload(REGO, &covered).unwrap();
            for _ in 0..BURST {
                let (mut connection, _) = upstream.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(connection.read_u8().await.unwrap());
                    assert!(header.len() < 8192);
                }
                assert!(header.starts_with(b"GET /missing?round="));
                connection
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
                let mut extra = Vec::new();
                connection.read_to_end(&mut extra).await.unwrap();
                assert!(extra.is_empty(), "no second exchange on this connection");
            }
        }
        End::Rejected => {
            reviewer.decision.store(2, Ordering::Release);
            engine.reload(REGO, &covered).unwrap();
        }
        End::ClientClosed => {
            for client in &mut clients {
                client.shutdown().await.unwrap();
            }
            // FIN sent is not native EOF observed. Assert retirement first;
            // the shared late-approval step below then proves no resurrection.
            // An approval racing an unobserved FIN is a different test outcome.
        }
        End::Disabled => {
            engine.set_http_hitl_wait_enabled(false);
            engine.set_http_hitl_wait_enabled(true);
            reviewer.decision.store(1, Ordering::Release);
            engine.reload(REGO, &covered).unwrap();
        }
        End::Deadline => {
            // Virtual time ONLY after actual socket ingress/capture: production
            // 300s remains unchanged. This is NOT a live elapsed-time claim.
            tokio::time::pause();
            tokio::time::advance(std::time::Duration::from_mins(5)).await;
        }
        End::ProxyShutdown => {
            drop(proxy.take());
        }
        End::ReviewUnavailable => {
            // Actual terminal adapter error, not a Retryable outage. Disconnect
            // only after all four Pending holds; fail closed without deadline.
            reviewer.unavailable.store(true, Ordering::Release);
            reviewer.decision.store(1, Ordering::Release);
            engine.reload(REGO, &covered).unwrap();
        }
    }
    for client in &mut clients {
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        if matches!(end, End::Response) {
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with(b"OK"));
        } else {
            assert!(
                response.is_empty(),
                "terminal request must not produce an upstream response"
            );
        }
    }
    if paused {
        tokio::time::resume();
    }
    drop(clients);
    tokio::task::yield_now().await;
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    let restored = census();
    if shutdown {
        assert!(exit.take().unwrap().await.is_err());
    }
    assert!(
        restored.tasks <= baseline.tasks + 1,
        "outer task census should recover to a bounded baseline: {restored:?} vs {baseline:?}"
    );
    // Late approval/coverage/service recovery cannot resurrect retired clients.
    reviewer.unavailable.store(false, Ordering::Release);
    reviewer.decision.store(1, Ordering::Release);
    engine.reload(REGO, &covered).unwrap();
    assert!(poll!(Box::pin(upstream.accept()).as_mut()).is_pending());
    println!(
        "RESOURCE_CENSUS round={round} end={end:?} baseline={baseline:?} held={held:?} restored={restored:?} invocations={BURST}"
    );
    if !shutdown {
        drop(proxy.take());
        assert!(exit.take().unwrap().await.is_err());
    }
    tokio::task::yield_now().await;
    assert_eq!(
        census().tasks,
        0,
        "no detached handler hidden by accept teardown"
    );
}

fn run(cases: &[End]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // These checks are intentionally bounded to the process-local task budget
        // and the terminal lifecycle contract. The test does not assume a global
        // process-wide resource census or a serialized execution order.
        let baseline = census();
        for (round, end) in cases.iter().enumerate() {
            tokio::time::timeout(std::time::Duration::from_mins(6), cycle(*end, round))
                .await
                .expect("resource cycle event/EOF timeout (includes virtual300s)");
            let after_cycle = census();
            assert!(
                after_cycle.tasks <= baseline.tasks + 1,
                "whole-cycle task budget should remain bounded: {after_cycle:?} vs {baseline:?}"
            );
        }
    });
}

#[test]
fn production_proxy_task_fd_census_all_terminal_paths() {
    run(&[
        End::Response,
        End::Rejected,
        End::ClientClosed,
        End::Disabled,
        End::Deadline,
        End::ProxyShutdown,
        End::ReviewUnavailable,
    ]);
}

#[test]
fn production_proxy_task_fd_census_bounded_160_original_requests() {
    let cases: Vec<_> = (0..40)
        .map(|round| {
            [
                End::Response,
                End::Rejected,
                End::ClientClosed,
                End::Disabled,
            ][round % 4]
        })
        .collect();
    run(&cases);
}

#[test]
fn task_census_tracks_abort_without_leaving_detached_task_leaks() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let baseline = census();
        let task = tokio::spawn(std::future::pending::<()>());
        tokio::task::yield_now().await;
        let spawned = census();
        assert!(spawned.tasks >= baseline.tasks + 1, "spawned task should be visible in the task census");
        assert_ne!(spawned, baseline);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let after_abort = census();
        assert!(after_abort.tasks <= baseline.tasks + 1, "task abort should leave a bounded task footprint");
    });
}
