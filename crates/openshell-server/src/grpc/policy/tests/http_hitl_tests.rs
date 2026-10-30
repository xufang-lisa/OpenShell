// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proposals::http_hitl_submission_fingerprint;
use openshell_core::proto::L7Allow;

fn hitl_chunk(path: &str) -> PolicyChunk {
    let rule_name = "http_hitl_read".to_string();
    let mut chunk = PolicyChunk {
        rule_name: rule_name.clone(),
        proposed_rule: Some(NetworkPolicyRule {
            name: rule_name,
            endpoints: vec![NetworkEndpoint {
                host: "example.com".into(),
                port: 8080,
                protocol: "rest".into(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "GET".into(),
                        path: path.into(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".into(),
            }],
        }),
        rationale: r#"{"generation":1}"#.into(),
        binary: "/usr/bin/curl".into(),
        stage: "http-hitl".into(),
        ..Default::default()
    };
    chunk.id = format!(
        "{}:{}",
        uuid::Uuid::new_v4(),
        http_hitl_submission_fingerprint(&chunk)
    );
    chunk
}

async fn submit(
    state: &Arc<ServerState>,
    name: &str,
    mode: &str,
    chunk: PolicyChunk,
) -> SubmitPolicyAnalysisResponse {
    Box::pin(handle_submit_policy_analysis(
        state,
        with_user(Request::new(SubmitPolicyAnalysisRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            name: name.into(),
            analysis_mode: mode.into(),
            proposed_chunks: vec![chunk],
            ..Default::default()
        })),
    ))
    .await
    .unwrap()
    .into_inner()
}

async fn stored(state: &Arc<ServerState>, id: &str) -> DraftChunkRecord {
    state.store.get_draft_chunk(id).await.unwrap().unwrap()
}

async fn durable_state(url: &str) -> Arc<ServerState> {
    let store = Arc::new(Store::connect(url).await.unwrap());
    crate::ensure_default_workspace(&store).await.unwrap();
    let compute = crate::compute::new_test_runtime(store.clone()).await;
    let mut state = ServerState::new(
        openshell_core::Config::new(None)
            .with_database_url(url)
            .with_credential_drivers(["test-static"]),
        store,
        compute,
        crate::sandbox_index::SandboxIndex::new(),
        crate::sandbox_watch::SandboxWatchBus::new(),
        crate::tracing_bus::TracingLogBus::new(),
        Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
        None,
    );
    state.provider_profile_sources = ProviderProfileSources::from_config(
        &[openshell_core::GatewayProviderProfileSourceConfig::User],
        None,
        None,
    )
    .unwrap();
    Arc::new(state)
}

#[tokio::test]
async fn http_hitl_lost_reply_retry_survives_database_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("hitl.db").display());
    let state = durable_state(&url).await;
    let name = "hitl-durable";
    seed_ready_sandbox(&state, name).await;
    let chunk = hitl_chunk("/items");
    // Discard the response, as when persistence succeeds but delivery fails.
    submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    let key = http_hitl_submission_key(&chunk).unwrap();
    let original = state
        .store
        .get_draft_chunk_by_dedup_key("sb-hitl-durable", &key)
        .await
        .unwrap()
        .unwrap();
    state.store.close().await;
    drop(state);

    let reopened = durable_state(&url).await;
    let retry = submit(&reopened, name, HTTP_HITL_ANALYSIS_MODE, chunk).await;
    assert_eq!(retry.accepted_chunk_ids, [original.id]);
    assert_eq!(
        reopened
            .store
            .list_draft_chunks("sb-hitl-durable", None)
            .await
            .unwrap()
            .len(),
        1
    );
    reopened.store.close().await;
}

#[tokio::test]
async fn http_hitl_concurrent_retries_share_one_stored_decision() {
    let state = test_server_state().await;
    let name = "hitl-concurrent";
    seed_ready_sandbox(&state, name).await;
    let chunk = hitl_chunk("/items");
    let (first, retry) = tokio::join!(
        submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()),
        submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk),
    );
    assert_eq!(first.accepted_chunks, 1, "{first:?}");
    assert_eq!(retry.accepted_chunk_ids, first.accepted_chunk_ids);
    assert_eq!(
        state
            .store
            .list_draft_chunks("sb-hitl-concurrent", None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn http_hitl_retry_preserves_edited_and_terminal_decisions() {
    let state = test_server_state().await;
    let name = "hitl-retry";
    seed_ready_sandbox(&state, name).await;
    let chunk = hitl_chunk("/items");
    let first = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    assert_eq!(first.accepted_chunks, 1, "{first:?}");
    let id = &first.accepted_chunk_ids[0];
    let retry = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    assert_eq!(retry.accepted_chunk_ids, first.accepted_chunk_ids);

    let mut edited_rule = chunk.proposed_rule.clone().unwrap();
    edited_rule.endpoints[0].rules[0]
        .allow
        .as_mut()
        .unwrap()
        .path = "/reviewed".into();
    handle_edit_draft_chunk(
        &state,
        with_user(Request::new(EditDraftChunkRequest {
            request_id: String::new(),
            sandbox: name.into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            chunk_id: id.clone(),
            proposed_rule: Some(edited_rule),
        })),
    )
    .await
    .unwrap();
    let edited = stored(&state, id).await;
    let retry = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    assert_eq!(retry.accepted_chunk_ids, first.accepted_chunk_ids);
    assert_eq!(stored(&state, id).await.proposed_rule, edited.proposed_rule);

    handle_reject_draft_chunk(
        &state,
        authed_request(RejectDraftChunkRequest {
            request_id: String::new(),
            sandbox: name.into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            chunk_id: id.clone(),
            reason: "operator decision".into(),
        }),
    )
    .await
    .unwrap();
    let retry = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk).await;
    assert_eq!(retry.accepted_chunk_ids, first.accepted_chunk_ids);
    let terminal = stored(&state, id).await;
    assert_eq!(terminal.status, "rejected");
    assert_eq!(terminal.rejection_reason, "operator decision");
    assert_eq!(terminal.proposed_rule, edited.proposed_rule);
    assert_eq!(
        state
            .store
            .list_draft_chunks("sb-hitl-retry", None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn http_hitl_distinct_paths_and_sessions_remain_pending() {
    let state = test_server_state().await;
    let name = "hitl-paths";
    seed_ready_sandbox(&state, name).await;
    let first_chunk = hitl_chunk("/items");
    let mut other_path = first_chunk.clone();
    other_path.proposed_rule.as_mut().unwrap().endpoints[0].rules[0]
        .allow
        .as_mut()
        .unwrap()
        .path = "/other".into();
    other_path.id = format!(
        "{}:{}",
        &first_chunk.id[..36],
        http_hitl_submission_fingerprint(&other_path)
    );
    let mut other_session = first_chunk.clone();
    other_session.id = format!("{}:{}", uuid::Uuid::new_v4(), &first_chunk.id[37..]);
    let mut ids = HashSet::new();
    for chunk in [first_chunk, other_path, other_session] {
        let response = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk).await;
        assert_eq!(response.accepted_chunks, 1, "{response:?}");
        assert!(ids.insert(response.accepted_chunk_ids[0].clone()));
    }
    for id in ids {
        assert_eq!(stored(&state, &id).await.status, "pending");
    }
}

#[tokio::test]
async fn http_hitl_same_declared_id_with_changed_content_is_rejected() {
    let state = test_server_state().await;
    let name = "hitl-altered";
    seed_ready_sandbox(&state, name).await;
    let chunk = hitl_chunk("/items");
    let first = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    assert_eq!(first.accepted_chunks, 1, "{first:?}");
    for change_candidate in [false, true] {
        let mut altered = chunk.clone();
        if change_candidate {
            altered.proposed_rule.as_mut().unwrap().endpoints[0].rules[0]
                .allow
                .as_mut()
                .unwrap()
                .path = "/changed".into();
        } else {
            altered.rationale = "changed metadata".into();
        }
        let response = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, altered).await;
        assert_eq!(response.accepted_chunks, 0);
        assert_eq!(response.rejected_chunks, 1);
        assert_eq!(
            response.rejection_reasons,
            ["invalid HTTP HITL submission identity"]
        );
    }
    assert_eq!(
        stored(&state, &first.accepted_chunk_ids[0]).await.status,
        "pending"
    );
}

#[tokio::test]
async fn http_hitl_requires_human_even_in_auto_mode() {
    let state = test_server_state().await;
    let name = "hitl-auto";
    seed_ready_sandbox(&state, name).await;
    seed_sandbox_approval_mode(&state, name, "auto").await;
    let response = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, hitl_chunk("/items")).await;
    assert_eq!(response.accepted_chunks, 1, "{response:?}");
    let record = stored(&state, &response.accepted_chunk_ids[0]).await;
    assert_eq!(record.validation_result, "prover: no new findings");
    assert_eq!(record.status, "pending");
    assert!(
        state
            .store
            .get_latest_policy("sb-hitl-auto")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn http_hitl_and_ordinary_endpoint_submissions_do_not_supersede_each_other() {
    let state = test_server_state().await;
    let name = "hitl-ordinary";
    seed_ready_sandbox(&state, name).await;
    let ordinary = submit_example_chunk(&state, name, "agent_authored").await;
    let hitl = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, hitl_chunk("/items")).await;
    assert_eq!(hitl.accepted_chunks, 1, "{hitl:?}");
    assert_eq!(stored(&state, &ordinary).await.status, "pending");
    let held = &hitl.accepted_chunk_ids[0];
    let mechanistic = submit_example_chunk(&state, name, "mechanistic").await;
    assert_ne!(&mechanistic, held);
    assert_eq!(
        stored(&state, &mechanistic).await.rule_name,
        "allow_example_8080"
    );
    assert_eq!(stored(&state, held).await.status, "pending");
    submit_example_chunk(&state, name, "agent_authored").await;
    assert_eq!(stored(&state, held).await.status, "pending");
}

#[tokio::test]
async fn http_hitl_approved_chunk_does_not_self_reject_mechanistic_observation() {
    let state = test_server_state().await;
    let name = "hitl-approved";
    seed_ready_sandbox(&state, name).await;
    let chunk = hitl_chunk("/items");
    let response = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk.clone()).await;
    assert_eq!(response.accepted_chunks, 1, "{response:?}");
    // Seed a terminal ledger state without installing a policy that would
    // independently cover the incoming rule during reconciliation.
    state
        .store
        .update_draft_chunk_status(
            &response.accepted_chunk_ids[0],
            "approved",
            Some(current_time_ms()),
            None,
        )
        .await
        .unwrap();
    let mechanistic = submit_example_chunk(&state, name, "mechanistic").await;
    assert_eq!(stored(&state, &mechanistic).await.status, "pending");
    let retry = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk).await;
    assert_eq!(retry.accepted_chunks, 1, "{retry:?}");
    assert_eq!(retry.accepted_chunk_ids, response.accepted_chunk_ids);
    assert_eq!(
        stored(&state, &response.accepted_chunk_ids[0]).await.status,
        "approved"
    );
}

#[tokio::test]
async fn http_hitl_valid_identity_still_requires_valid_candidate() {
    let state = test_server_state().await;
    let name = "hitl-invalid";
    seed_ready_sandbox(&state, name).await;
    let mut chunk = hitl_chunk("/items");
    chunk.proposed_rule.as_mut().unwrap().endpoints[0].port = 70_000;
    chunk.id = format!(
        "{}:{}",
        uuid::Uuid::new_v4(),
        http_hitl_submission_fingerprint(&chunk)
    );
    let response = submit(&state, name, HTTP_HITL_ANALYSIS_MODE, chunk).await;
    assert_eq!(response.accepted_chunks, 0);
    assert_eq!(response.rejected_chunks, 1);
}
