// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, no-release HTTP waiting. There is deliberately no write permission,
//! approval consumer, background poller, or resumable upstream in this module.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitEnd {
    Deadline,
    ClientClosed,
    ExtraInput,
    ClientError,
    Disabled,
    Quarantined,
    Shutdown,
    ProposalUnavailable,
}

struct Population {
    enabled: bool,
    quarantined: bool,
    shutdown: bool,
    epoch: u64,
    last_terminal: WaitEnd,
    total: usize,
    // Conservatively share one scope across ALL binaries at a destination.
    // Do not guess the authoritative ancestor scope from a display path.
    destinations: HashMap<(String, u16), usize>,
}

pub struct WaitRuntime {
    population: Mutex<Population>,
    proposal_service: Mutex<Option<Arc<dyn super::proposal::HeldProposalService>>>,
    changed: watch::Sender<u64>,
    budget: Duration,
    sandbox_limit: usize,
    destination_limit: usize,
}

impl Default for WaitRuntime {
    fn default() -> Self {
        Self::with_limits(Duration::from_mins(5), 16, 4)
            .expect("fixed HTTP wait limits satisfy the safety caps")
    }
}

impl WaitRuntime {
    fn with_limits(budget: Duration, sandbox: usize, destination: usize) -> miette::Result<Self> {
        if budget.is_zero()
            || budget > Duration::from_mins(5)
            || sandbox == 0
            || sandbox > 16
            || destination == 0
            || destination > 4
        {
            return Err(miette::miette!("HTTP wait limits must tighten 300s/16/4"));
        }
        Ok(Self {
            proposal_service: Mutex::new(None),
            population: Mutex::new(Population {
                enabled: false,
                quarantined: false,
                shutdown: false,
                epoch: 0,
                last_terminal: WaitEnd::Disabled,
                total: 0,
                destinations: HashMap::new(),
            }),
            changed: watch::channel(0).0,
            budget,
            sandbox_limit: sandbox,
            destination_limit: destination,
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.population
            .lock()
            .is_ok_and(|state| state.enabled && !state.shutdown)
    }

    pub(crate) fn set_proposal_service(
        &self,
        service: Arc<dyn super::proposal::HeldProposalService>,
    ) {
        *self
            .proposal_service
            .lock()
            .expect("HTTP proposal service lock poisoned") = Some(service);
    }

    pub(crate) fn proposal_service(&self) -> Option<Arc<dyn super::proposal::HeldProposalService>> {
        self.proposal_service.lock().ok()?.clone()
    }

    pub(crate) fn configure(&self, enabled: bool) {
        if let Ok(mut state) = self.population.lock() {
            if state.enabled && !enabled {
                state.epoch += 1;
                state.last_terminal = WaitEnd::Disabled;
                self.changed.send_replace(state.epoch);
            }
            state.enabled = enabled;
        }
    }

    pub(crate) fn quarantine(&self) {
        self.cancel(WaitEnd::Quarantined);
    }

    pub(crate) fn recover(&self) {
        if let Ok(mut state) = self.population.lock() {
            state.quarantined = false;
        }
    }

    fn cancel(&self, reason: WaitEnd) {
        if let Ok(mut state) = self.population.lock() {
            state.quarantined |= reason == WaitEnd::Quarantined;
            state.shutdown |= reason == WaitEnd::Shutdown;
            state.epoch += 1;
            state.last_terminal = reason;
            self.changed.send_replace(state.epoch);
        }
    }

    pub(crate) fn shutdown_guard(self: &Arc<Self>) -> WaitShutdown {
        WaitShutdown(self.clone())
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        captured_at: Instant,
    ) -> Option<WaitReservation> {
        let host = host.trim_end_matches('.');
        if host.is_empty() || port == 0 {
            return None;
        }
        let host = host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| host.to_ascii_lowercase(), |address| address.to_string());
        let key = (host, port);
        let deadline = captured_at.checked_add(self.budget)?;
        let mut state = self.population.lock().ok()?;
        if !state.enabled
            || state.quarantined
            || state.shutdown
            || Instant::now() >= deadline
            || state.total >= self.sandbox_limit
            || state.destinations.get(&key).copied().unwrap_or(0) >= self.destination_limit
        {
            return None;
        }
        state.total += 1;
        *state.destinations.entry(key.clone()).or_default() += 1;
        Some(WaitReservation {
            runtime: self.clone(),
            key,
            epoch: state.epoch,
            deadline,
        })
    }

    #[cfg(test)]
    pub(crate) fn population(&self) -> usize {
        self.population.lock().unwrap().total
    }
}

/// Move into the proxy task BEFORE spawning: even abort-before-first-poll
/// drops the captured guard and terminates waiters on runtime/session loss.
pub struct WaitShutdown(Arc<WaitRuntime>);

impl Drop for WaitShutdown {
    fn drop(&mut self) {
        self.0.cancel(WaitEnd::Shutdown);
    }
}

/// Not Clone: one waiter, one charge. The transport must be dropped BEFORE
/// this reservation. `HttpSession` field order enforces that for owned streams.
pub struct WaitReservation {
    runtime: Arc<WaitRuntime>,
    key: (String, u16),
    epoch: u64,
    deadline: Instant,
}

impl WaitReservation {
    pub(crate) fn proposal_service(&self) -> Option<Arc<dyn super::proposal::HeldProposalService>> {
        self.runtime.proposal_service()
    }

    pub(crate) fn destination(&self) -> (&str, u16) {
        (&self.key.0, self.key.1)
    }

    pub(crate) async fn wait<C: AsyncRead + Unpin>(&self, client: &mut BufReader<C>) -> WaitEnd {
        let mut changed = self.runtime.changed.subscribe();
        loop {
            let terminal =
                self.runtime
                    .population
                    .lock()
                    .map_or(Some(WaitEnd::Shutdown), |state| {
                        (state.epoch != self.epoch
                            || state.shutdown
                            || state.quarantined
                            || !state.enabled)
                            .then_some(state.last_terminal)
                    });
            if let Some(reason) = terminal {
                return reason;
            }
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(self.deadline) => return WaitEnd::Deadline,
                result = changed.changed() => {
                    if result.is_err() { return WaitEnd::Shutdown; }
                }
                result = client.fill_buf() => return match result {
                    Ok([]) => WaitEnd::ClientClosed,
                    Ok(_) => WaitEnd::ExtraInput,
                    Err(_) => WaitEnd::ClientError,
                },
            }
        }
    }
}

impl Drop for WaitReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.runtime.population.lock() {
            state.total -= 1;
            if let Some(count) = state.destinations.get_mut(&self.key) {
                *count -= 1;
                if *count == 0 {
                    state.destinations.remove(&self.key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use tokio::io::AsyncWriteExt;

    fn runtime() -> Arc<WaitRuntime> {
        let runtime = Arc::new(WaitRuntime::default());
        runtime.configure(true);
        runtime
    }

    #[test]
    fn limits_fail_closed_and_disabled_has_no_population() {
        for (seconds, sandbox, destination) in [
            (0, 16, 4),
            (301, 16, 4),
            (300, 17, 4),
            (300, 16, 5),
            (300, 0, 4),
            (300, 16, 0),
        ] {
            assert!(
                WaitRuntime::with_limits(Duration::from_secs(seconds), sandbox, destination)
                    .is_err()
            );
        }
        let runtime = Arc::new(WaitRuntime::default());
        assert!(runtime.reserve("example.com", 80, Instant::now()).is_none());
        assert_eq!(runtime.population(), 0);
    }

    #[test]
    fn reservations_atomically_enforce_both_limits_without_partial_overdraw() {
        let runtime = runtime();
        let mut charges = Vec::new();
        for destination in 0..4 {
            for _ in 0..4 {
                charges.push(
                    runtime
                        .reserve(&format!("host-{destination}"), 80, Instant::now())
                        .unwrap(),
                );
            }
            assert!(
                runtime
                    .reserve(&format!("HOST-{destination}."), 80, Instant::now())
                    .is_none()
            );
        }
        assert_eq!(runtime.population(), 16);
        assert!(runtime.reserve("other", 80, Instant::now()).is_none());
        drop(charges.pop());
        assert_eq!(runtime.population(), 15);
        assert!(runtime.reserve("other", 80, Instant::now()).is_some());
        drop(charges);
        assert_eq!(runtime.population(), 0);
        assert!(runtime.population.lock().unwrap().destinations.is_empty());
    }

    #[test]
    fn concurrent_admission_never_overdraws_a_destination() {
        let runtime = runtime();
        let attempted = Arc::new(std::sync::Barrier::new(32));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let runtime = runtime.clone();
                let attempted = attempted.clone();
                std::thread::spawn(move || {
                    let charge = runtime.reserve("EXAMPLE.com.", 80, Instant::now());
                    attempted.wait();
                    assert!(runtime.population() <= 4);
                    charge.is_some()
                })
            })
            .collect();
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 4);
        assert_eq!(runtime.population(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_from_capture_not_admission_or_wakeup_and_charge_survives_exit() {
        let runtime = runtime();
        let captured = Instant::now();
        tokio::time::advance(Duration::from_secs(290)).await;
        let charge = runtime.reserve("example.com", 80, captured).unwrap();
        let (_wire, client) = tokio::io::duplex(8192);
        let mut reader = BufReader::new(client);
        let wait = charge.wait(&mut reader);
        tokio::pin!(wait);
        assert!(poll!(wait.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(wait.await, WaitEnd::Deadline);
        assert_eq!(runtime.population(), 1);
        assert!(runtime.reserve("other", 80, captured).is_none());
    }

    #[tokio::test]
    async fn transient_quarantine_and_disable_cannot_be_missed() {
        for quarantine in [false, true] {
            let runtime = runtime();
            let charge = runtime.reserve("example.com", 80, Instant::now()).unwrap();
            if quarantine {
                runtime.quarantine();
                runtime.recover();
            } else {
                runtime.configure(false);
                runtime.configure(true);
            }
            let (_wire, client) = tokio::io::duplex(8192);
            assert_eq!(
                charge.wait(&mut BufReader::new(client)).await,
                if quarantine {
                    WaitEnd::Quarantined
                } else {
                    WaitEnd::Disabled
                }
            );
            assert_eq!(runtime.population(), 1);
        }
    }

    #[tokio::test]
    async fn task_abort_even_before_first_poll_cancels_the_wait_cohort() {
        let runtime = runtime();
        let charge = runtime.reserve("example.com", 80, Instant::now()).unwrap();
        let guard = runtime.shutdown_guard();
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let (_wire, client) = tokio::io::duplex(8192);
        assert_eq!(
            charge.wait(&mut BufReader::new(client)).await,
            WaitEnd::Shutdown
        );
    }

    #[tokio::test]
    async fn extra_input_eof_and_runtime_loss_are_terminal_without_consuming_input() {
        for mode in 0..3 {
            let runtime = runtime();
            let charge = runtime.reserve("example.com", 80, Instant::now()).unwrap();
            let (mut wire, client) = tokio::io::duplex(8192);
            let mut reader = BufReader::new(client);
            let expected = match mode {
                0 => {
                    wire.write_all(b"second-request").await.unwrap();
                    WaitEnd::ExtraInput
                }
                1 => {
                    wire.shutdown().await.unwrap();
                    WaitEnd::ClientClosed
                }
                _ => {
                    drop(runtime.shutdown_guard());
                    WaitEnd::Shutdown
                }
            };
            assert_eq!(charge.wait(&mut reader).await, expected);
            if mode == 0 {
                assert_eq!(reader.buffer(), b"second-request");
            }
            assert_eq!(runtime.population(), 1);
            drop(reader);
            drop(charge);
            assert_eq!(runtime.population(), 0);
        }
    }
}
