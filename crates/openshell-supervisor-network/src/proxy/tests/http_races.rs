// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real TCP FIN versus simulated approval/installation, through the production
//! direct-listener accept/spawn and full held exchange. No live human decision,
//! TLS, durable Gateway ledger, native mediation provenance or business effect.

use super::http_resources::census;
use super::*;
use futures::poll;
use openshell_ocsf::test_support::OcsfCapture;
use serde_json::Value;
use tokio::sync::Notify;
use tracing_subscriber::layer::SubscriberExt;

const REGO: &str = include_str!("../../../data/sandbox-policy.rego");

#[derive(Default)]
struct RaceReviewer {
    approved: std::sync::atomic::AtomicBool,
    submissions: AtomicU32,
    pending: Notify,
}

impl crate::l7::proposal::HeldProposalService for RaceReviewer {
    fn submit<'a>(
        &'a self,
        _: &'a crate::l7::proposal::HeldProposalInput,
    ) -> crate::l7::proposal::ProposalSubmission<'a> {
        Box::pin(async move {
            self.submissions.fetch_add(1, Ordering::AcqRel);
            Ok("simulated-race-chunk".into())
        })
    }

    fn observe<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> crate::l7::proposal::ProposalObservation<'a> {
        Box::pin(async move {
            if self.approved.load(Ordering::Acquire) {
                Ok(crate::l7::proposal::ReviewDecision::Approved)
            } else {
                self.pending.notify_one();
                Ok(crate::l7::proposal::ReviewDecision::Pending)
            }
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Order {
    ObservedCloseThenApprove,
    FirstHttpByteThenClose,
    FreshAcceptThenClose,
    FinSentThenApproveWithoutEofBarrier,
}

#[derive(Debug, Clone)]
struct Evidence {
    dials: usize,
    bytes: usize,
    wait_terminals: Vec<String>,
    readmissions: usize,
    exchanges: Vec<String>,
}

fn valid(e: &Evidence) -> bool {
    if e.dials > 1 || e.readmissions > 1 || e.exchanges.len() > 1 {
        return false;
    }
    if !e.wait_terminals.is_empty() {
        return e.wait_terminals.len() == 1
            && e.wait_terminals[0].contains("terminal=ClientClosed;")
            && e.dials == 0
            && e.bytes == 0
            && e.readmissions == 0
            && e.exchanges.is_empty();
    }
    e.readmissions == 1
        && e.exchanges.len() == 1
        && match e.exchanges[0].as_str() {
            "not_sent" => e.bytes == 0,
            "effect_unknown" => e.dials == 1 && e.bytes > 0,
            _ => false,
        }
}

async fn exchange(order: Order, round: usize, capture: &OcsfCapture) -> Evidence {
    let event_offset = capture.events().len();
    let ip: Ipv4Addr = std::env::var("OPENSHELL_HTTP_RESOURCE_TEST_IP").map_or_else(
        |_| non_loopback_test_ipv4().expect("race fixture needs local IPv4"),
        |ip| ip.parse().expect("race fixture IPv4 override"),
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
    let reviewer = Arc::new(RaceReviewer::default());
    engine.set_http_hitl_proposal_service(reviewer.clone());
    let (_ready, ready) = tokio::sync::watch::channel(true);
    let mut proxy = ProxyHandle::start_with_bind_addr(
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
    .unwrap();
    let exit = proxy.take_exit_receiver().unwrap();
    tokio::task::yield_now().await;
    let baseline = census();
    assert_eq!(baseline.tasks, 1);
    let mut client = TcpStream::connect(proxy.http_addr().unwrap())
        .await
        .unwrap();
    client.write_all(format!("GET http://{destination}/missing?case={round} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes()).await.unwrap();
    reviewer.pending.notified().await;
    assert_eq!(engine.http_hitl_wait_runtime().population(), 1);
    let held = census();
    assert!(held.tasks >= baseline.tasks + 1, "held tasks should include the pending session handler");
    assert!(poll!(Box::pin(upstream.accept()).as_mut()).is_pending());
    let approve = || {
        reviewer.approved.store(true, Ordering::Release);
        engine.reload(REGO, &covered).unwrap();
    };
    let mut peer = None;
    let mut bytes = Vec::new();
    let mut response = Vec::new();
    match order {
        Order::ObservedCloseThenApprove => {
            client.shutdown().await.unwrap();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
            approve();
        }
        Order::FirstHttpByteThenClose => {
            approve();
            let (mut connection, _) = upstream.accept().await.unwrap();
            bytes.push(connection.read_u8().await.unwrap());
            assert_eq!(bytes, b"G", "positive HTTP-byte barrier before FIN");
            client.shutdown().await.unwrap();
            peer = Some(connection);
        }
        Order::FreshAcceptThenClose => {
            approve();
            let (connection, _) = upstream.accept().await.unwrap();
            // Accept is a dial barrier, NOT proof of zero/positive HTTP write.
            client.shutdown().await.unwrap();
            peer = Some(connection);
        }
        Order::FinSentThenApproveWithoutEofBarrier => {
            client.shutdown().await.unwrap();
            // No yield/EOF observation between actual FIN and installation.
            // Either native winner is valid; classify, never force not_sent.
            approve();
        }
    }
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        response.is_empty(),
        "fixture intentionally never sends a response"
    );
    // EOF retired the producer. Inspect the actual kernel backlog, not just
    // Tokio's cached readiness flag, when accounting an unobserved fresh dial.
    let upstream = upstream.into_std().unwrap();
    if peer.is_none() {
        match upstream.accept() {
            Ok((connection, _)) => {
                connection.set_nonblocking(true).unwrap();
                peer = Some(TcpStream::from_std(connection).unwrap());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("post-EOF kernel backlog inspection: {error}"),
        }
    }
    let dials = usize::from(peer.is_some());
    if let Some(mut peer) = peer {
        peer.read_to_end(&mut bytes).await.unwrap();
    }
    assert!(bytes.len() < 8192);
    assert!(
        bytes.windows(4).filter(|part| *part == b"\r\n\r\n").count() <= 1,
        "no second request on original upstream"
    );
    assert_eq!(
        upstream.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "no second fresh dial/replay"
    );
    drop(client);
    tokio::task::yield_now().await;
    assert_eq!(engine.http_hitl_wait_runtime().population(), 0);
    let retired = census();
    assert!(
        retired.tasks <= baseline.tasks + 1,
        "held handler should retire without leaving a detached task behind: {retired:?} vs {baseline:?}"
    );
    let events: Vec<Value> = capture
        .events()
        .iter()
        .skip(event_offset)
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let admitted: Vec<_> = events
        .iter()
        .filter(|e| {
            e["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("HTTP_HITL_WAIT admitted"))
        })
        .collect();
    assert_eq!(admitted.len(), 1);
    let request_id = admitted[0]["unmapped"]["request_id"].as_str().unwrap();
    let scoped: Vec<_> = events
        .iter()
        .filter(|e| e["unmapped"]["request_id"].as_str() == Some(request_id))
        .collect();
    let select = |prefix: &str| {
        scoped
            .iter()
            .filter(|e| e["message"].as_str().is_some_and(|m| m.starts_with(prefix)))
            .map(|e| (*e).clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(select("HTTP_HITL_PROPOSAL accepted").len(), 1);
    assert_eq!(reviewer.submissions.load(Ordering::Acquire), 1);
    let readmissions = select("HTTP_HITL_READMISSION");
    let exchanges = select("HTTP_HITL_EXCHANGE");
    let terminal = select("HTTP_HITL_WAIT terminal=");
    let evidence = Evidence {
        dials,
        bytes: bytes.len(),
        readmissions: readmissions.len(),
        wait_terminals: terminal
            .iter()
            .map(|e| e["message"].as_str().unwrap().to_owned())
            .collect(),
        exchanges: exchanges
            .iter()
            .map(|e| e["unmapped"]["outcome"].as_str().unwrap().to_owned())
            .collect(),
    };
    assert!(
        valid(&evidence),
        "native result must match actual peer bytes: {evidence:?}"
    );
    match order {
        Order::ObservedCloseThenApprove => assert_eq!(
            (
                dials,
                evidence.bytes,
                evidence.readmissions,
                evidence.exchanges.len()
            ),
            (0, 0, 0, 0)
        ),
        Order::FirstHttpByteThenClose => {
            assert_eq!(dials, 1);
            assert!(evidence.bytes > 0);
            assert_eq!(evidence.exchanges, ["effect_unknown"]);
        }
        Order::FreshAcceptThenClose => assert_eq!(dials, 1),
        Order::FinSentThenApproveWithoutEofBarrier => {}
    }
    // Reload after actual retirement cannot resurrect this original Q.
    approve();
    assert_eq!(
        upstream.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let post_approve = census();
    assert!(
        post_approve.tasks <= baseline.tasks + 1,
        "post-approval state must not leak detached tasks: {post_approve:?} vs {baseline:?}"
    );
    assert_eq!(select("HTTP_HITL_SESSION").len(), 2);
    let native: Vec<_> = scoped
        .iter()
        .map(|e| serde_json::json!({"message":e["message"],"unmapped":e["unmapped"]}))
        .collect();
    println!(
        "FIN_RACE {}",
        serde_json::json!({"round":round,"order":format!("{order:?}"),"request_id":request_id,"dials":dials,"http_bytes":evidence.bytes,"readmissions":evidence.readmissions,"wait_terminals":evidence.wait_terminals,"exchanges":evidence.exchanges,"baseline_tasks":baseline.tasks,"baseline_fds":baseline.fds,"baseline_sockets":baseline.sockets,"held_tasks":held.tasks,"held_fds":held.fds,"held_sockets":held.sockets,"retired_tasks":retired.tasks,"retired_fds":retired.fds,"retired_sockets":retired.sockets,"quota_final":engine.http_hitl_wait_runtime().population(),"native":native})
    );
    drop(proxy);
    assert!(exit.await.is_err());
    tokio::task::yield_now().await;
    assert_eq!(census().tasks, 0);
    evidence
}

fn run(orders: &[Order]) -> Vec<Evidence> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let capture = OcsfCapture::default();
    // Scope the event capture to the current test execution instead of mutating
    // the process-wide default subscriber. The assertions here are semantic
    // behavior checks, not a requirement that the whole test binary be serialized.
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let baseline = census();
            let mut results = Vec::new();
            for (round, order) in orders.iter().enumerate() {
                results.push(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        exchange(*order, round, &capture),
                    )
                    .await
                    .expect("FIN race event/EOF timeout"),
                );
                let after_cycle = census();
                assert!(
                    after_cycle.tasks <= baseline.tasks + 1,
                    "per-cycle task budget should remain bounded: {after_cycle:?} vs {baseline:?}"
                );
            }
            results
        })
    })
}

#[test]
fn fin_race_native_cancel_observed_and_positive_http_write_controls() {
    let orders: Vec<_> = (0..32)
        .map(|i| {
            if i % 2 == 0 {
                Order::ObservedCloseThenApprove
            } else {
                Order::FirstHttpByteThenClose
            }
        })
        .collect();
    run(&orders);
}

#[test]
fn fin_race_native_unordered_winners_match_actual_peer_bytes() {
    let orders: Vec<_> = (0..64)
        .map(|i| {
            if i % 2 == 0 {
                Order::FreshAcceptThenClose
            } else {
                Order::FinSentThenApproveWithoutEofBarrier
            }
        })
        .collect();
    run(&orders);
}

#[test]
fn fin_race_evidence_rejects_false_not_sent_and_duplicate_exchange() {
    let original = run(&[Order::FirstHttpByteThenClose]).pop().unwrap();
    let mut false_not_sent = original.clone();
    false_not_sent.exchanges = vec!["not_sent".into()];
    assert!(!valid(&false_not_sent));
    let mut duplicate = original.clone();
    duplicate.exchanges.push("effect_unknown".into());
    assert!(!valid(&duplicate));
    let mut no_bytes = original;
    no_bytes.bytes = 0;
    assert!(!valid(&no_bytes));
}
