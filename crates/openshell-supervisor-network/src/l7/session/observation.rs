// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Passive held-owner accounting, independent of wait quota and authorization.
//! Counts session-owned lifecycles, not all proxy/Tokio tasks or open FDs.

use openshell_ocsf::{BaseEventBuilder, SeverityId, ocsf_emit};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    active: usize,
    sequence: u64,
}

#[derive(Default)]
pub struct HeldSessionTracker(Mutex<State>);

impl HeldSessionTracker {
    pub(crate) fn configuration_snapshot(&self) {
        self.record("configuration", None, 0);
    }

    pub(crate) fn start(
        self: &Arc<Self>,
        request_id: String,
        reservation_id: String,
    ) -> HeldSession {
        let owner = HeldSession {
            tracker: self.clone(),
            request_id,
            reservation_id,
        };
        self.record("started", Some(&owner), 1);
        owner
    }

    fn record(&self, action: &str, owner: Option<&HeldSession>, delta: i8) {
        // Observation cannot reject admission or alter the runtime cancel epoch.
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match delta {
            1 => state.active += 1,
            -1 => state.active -= 1,
            _ => {}
        }
        state.sequence = state.sequence.wrapping_add(1);
        let (active, sequence) = (state.active, state.sequence);
        drop(state);
        ocsf_emit!(build_snapshot(action, owner, active, sequence));
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.0.lock().unwrap().active
    }
}

fn build_snapshot(
    action: &str,
    owner: Option<&HeldSession>,
    active: usize,
    sequence: u64,
) -> openshell_ocsf::OcsfEvent {
    let mut event = BaseEventBuilder::new(openshell_ocsf::ctx::ctx())
        .activity_name("HTTP HITL held owner population")
        .severity(SeverityId::Informational)
        .unmapped("session_action", serde_json::json!(action))
        .unmapped("active_held_sessions", serde_json::json!(active))
        .unmapped(
            "lifecycle_sequence",
            serde_json::json!(sequence.to_string()),
        );
    if let Some(owner) = owner {
        event = event
            .unmapped("request_id", serde_json::json!(owner.request_id))
            .unmapped("reservation_id", serde_json::json!(owner.reservation_id));
    }
    event
        .message("HTTP_HITL_SESSION lifecycle snapshot; not a task census or execution authority")
        .build()
}

/// Not Clone. `RequestSlot`'s LAST field: client, frozen input and reservation
/// must already be retired before this owner's final passive snapshot.
pub struct HeldSession {
    tracker: Arc<HeldSessionTracker>,
    request_id: String,
    reservation_id: String,
}

impl Drop for HeldSession {
    fn drop(&mut self) {
        self.tracker.record("retired", Some(self), -1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_bind_zero_baseline_and_distinct_overlapping_owners() {
        // Assert the exact production builder without a parallel test's global
        // tracing-interest cache deciding whether this local sink is enabled.
        let tracker = Arc::new(HeldSessionTracker::default());
        tracker.configuration_snapshot();
        let baseline = build_snapshot("configuration", None, tracker.active(), 1);
        let first = tracker.start("request-a".into(), "reservation-a".into());
        let started_first = build_snapshot("started", Some(&first), tracker.active(), 2);
        let second = tracker.start("request-b".into(), "reservation-b".into());
        let started_second = build_snapshot("started", Some(&second), tracker.active(), 3);
        let retired_first = build_snapshot("retired", Some(&first), 1, 4);
        drop(first);
        assert_eq!(tracker.active(), 1);
        let retired_second = build_snapshot("retired", Some(&second), 0, 5);
        drop(second);
        assert_eq!(tracker.active(), 0);
        let records: Vec<serde_json::Value> = [
            baseline,
            started_first,
            started_second,
            retired_first,
            retired_second,
        ]
        .into_iter()
        .map(|event| event.to_json().unwrap())
        .collect();
        assert_eq!(records.len(), 5);
        for (index, count) in [0, 1, 2, 1, 0].into_iter().enumerate() {
            assert_eq!(records[index]["unmapped"]["active_held_sessions"], count);
            assert_eq!(
                records[index]["unmapped"]["lifecycle_sequence"],
                (index + 1).to_string()
            );
        }
        assert_eq!(records[0]["unmapped"].as_object().unwrap().len(), 3);
        for record in &records[1..] {
            assert_eq!(record["unmapped"].as_object().unwrap().len(), 5);
        }
        assert_eq!(
            records[1]["unmapped"]["request_id"],
            records[3]["unmapped"]["request_id"]
        );
        assert_eq!(
            records[2]["unmapped"]["reservation_id"],
            records[4]["unmapped"]["reservation_id"]
        );
    }

    #[tokio::test]
    async fn owned_client_drops_before_reservation_and_observation() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, BufReader, DuplexStream, ReadBuf};

        struct Client {
            inner: DuplexStream,
            runtime: Arc<crate::l7::wait::WaitRuntime>,
        }
        impl AsyncRead for Client {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }
        impl Drop for Client {
            fn drop(&mut self) {
                assert_eq!(self.runtime.population(), 1);
                assert_eq!(self.runtime.held_session_tracker().active(), 1);
            }
        }
        let runtime = Arc::new(crate::l7::wait::WaitRuntime::default());
        runtime.configure(true);
        let reservation = runtime
            .reserve("example.test", 80, tokio::time::Instant::now())
            .unwrap();
        let mut slot = crate::l7::session::RequestSlot::new();
        slot.held_session = Some(
            runtime
                .held_session_tracker()
                .start("request".into(), reservation.id().to_owned()),
        );
        slot.waiter = Some(reservation);
        let (_wire, inner) = tokio::io::duplex(64);
        let client = Client {
            inner,
            runtime: runtime.clone(),
        };
        drop(crate::l7::session::HttpSession::from_reader(
            BufReader::new(client),
            slot,
        ));
        assert_eq!(runtime.population(), 0);
        assert_eq!(runtime.held_session_tracker().active(), 0);
    }
}
