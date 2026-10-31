//! The engine-A relay-bridge doors: what they refuse, what they serve, and
//! that a dropped caller cannot cut an apply in half.

use super::issue1269_shutdown_apply_boundary::{leftover_temp_files, persisted_has, wait_reached};
use super::*;

const WAIT: Duration = Duration::from_secs(15);
const GROUP: &str = "engine-a-door-local-key";
const STABLE: &str = "engine-a-door-stable-id";
const RENAMED: &str = "engine-a door rename";

async fn install_group(state: &Arc<AppState>) -> Result<x0x::groups::GroupInfo> {
    let (mut info, admin_hex, _) = metadata_terminality_test_group(state, GROUP);
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        STABLE.to_string(),
        admin_hex,
        info.created_at,
        String::new(),
    ));
    info.metadata_topic = "local:engine-a-door".to_string();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info.clone());
    anyhow::ensure!(
        save_named_groups(state).await,
        "the group is persisted before the door applies"
    );
    anyhow::ensure!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(info)
}

fn signed_rename(
    state: &Arc<AppState>,
    parent: &x0x::groups::GroupInfo,
) -> NamedGroupMetadataEvent {
    let mut next = parent.clone();
    next.name = RENAMED.to_string();
    next.roster_revision += 1;
    NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: STABLE.to_string(),
        revision: next.roster_revision,
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            parent,
            &next,
            state,
            now_millis_u64(),
        )),
    }
}

fn door_request(
    state: &AppState,
    event: &NamedGroupMetadataEvent,
) -> Result<ApplyMetadataEventRequest> {
    Ok(ApplyMetadataEventRequest {
        event_b64: BASE64.encode(serde_json::to_vec(event)?),
        sender_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
    })
}

async fn body_of(response: axum::response::Response) -> Result<(StatusCode, serde_json::Value)> {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// The caller of the apply door goes away while the apply is parked inside
/// its atomic named-groups write. The apply still runs to completion: the
/// file holds the rename, no temp file is left, and memory agrees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_survives_a_dropped_caller() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let path = state.named_groups_path.clone();
    let request = door_request(&state, &signed_rename(&state, &parent))?;
    let pause = atomic_write_test_seam::arm(&path);

    let caller_state = Arc::clone(&state);
    let caller = tokio::spawn(async move {
        apply_group_metadata_event(State(caller_state), Path(STABLE.to_string()), Json(request))
            .await
            .into_response()
    });
    anyhow::ensure!(
        wait_reached(&pause).await,
        "the door's apply parks in its named-groups write"
    );
    caller.abort();
    anyhow::ensure!(caller.await.is_err(), "the caller was dropped mid-apply");
    pause.release();

    let deadline = tokio::time::Instant::now() + WAIT;
    while !(persisted_has(&path, RENAMED) && leftover_temp_files(&path).is_empty()) {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the dropped caller's apply must finish its write"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let name = state
        .named_groups
        .read()
        .await
        .get(GROUP)
        .map(|info| info.name.clone());
    assert_eq!(name.as_deref(), Some(RENAMED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_answers_422_with_a_reason_for_an_unsigned_event() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let mut event = signed_rename(&state, &parent);
    if let NamedGroupMetadataEvent::GroupMetadataUpdated { commit, .. } = &mut event {
        *commit = None;
    }
    let response = apply_group_metadata_event(
        State(Arc::clone(&state)),
        Path(STABLE.to_string()),
        Json(door_request(&state, &event)?),
    )
    .await
    .into_response();
    let (status, body) = body_of(response).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["reason"].as_str(),
        Some("unsigned_event_needs_verified_sender")
    );
    assert!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_apply_door_answers_422_for_a_legacy_removal_and_admits_a_self_leave_seal(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state).await?;
    let bytes = b"treekem commit bytes";
    let removal = |binding: String| {
        let mut next = parent.clone();
        next.roster_revision += 1;
        let mut commit = sign_metadata_terminality_commit(&parent, &next, &state, now_millis_u64());
        commit.security_binding = Some(binding);
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: STABLE.to_string(),
            revision: next.roster_revision,
            actor: hex::encode(state.agent.agent_id().as_bytes()),
            agent_id: "bb".repeat(32),
            treekem_commit_b64: Some(BASE64.encode(bytes)),
            treekem_epoch: Some(5),
            secret_epoch: None,
            commit: Some(commit),
        }
    };

    let legacy = apply_group_metadata_event(
        State(Arc::clone(&state)),
        Path(STABLE.to_string()),
        Json(door_request(
            &state,
            &removal("treekem:epoch=5".to_string()),
        )?),
    )
    .await
    .into_response();
    let (status, body) = body_of(legacy).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["reason"].as_str(),
        Some("needs_verified_signer_and_named_tree_bytes")
    );

    let sealed = apply_group_metadata_event(
        State(Arc::clone(&state)),
        Path(STABLE.to_string()),
        Json(door_request(
            &state,
            &removal(treekem_commit_binding(5, bytes)),
        )?),
    )
    .await
    .into_response();
    let (status, _) = body_of(sealed).await?;
    assert_ne!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a stock self-leave seal names its bytes, so the door lets it through to the apply"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_get_answers_404_group_unknown() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let response = get_join_result_inline(
        State(Arc::clone(&state)),
        Path(("no-such-group".to_string(), "cc".repeat(32))),
    )
    .await
    .into_response();
    let (status, body) = body_of(response).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"].as_str(), Some("group_unknown"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_join_result_get_runs_the_serving_guard_before_it_serves() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    install_group(&state).await?;
    let stranger = "dd".repeat(32);
    let response = get_join_result_inline(
        State(Arc::clone(&state)),
        Path((STABLE.to_string(), stranger.clone())),
    )
    .await
    .into_response();
    let (status, body) = body_of(response).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the 409 names its reason: {body}"
    );
    Ok(())
}

/// A session bearer is refused 403 at the route layer, ahead of any body
/// parse; the durable token passes the gate and meets the handler's own
/// validation (a malformed body answers 400, never 403).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_a_doors_refuse_a_session_bearer_before_the_body_is_parsed() -> Result<()> {
    use axum::http::Request;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let app = axum::Router::new()
        .route(
            "/groups/:id/apply-metadata-event",
            post(apply_group_metadata_event),
        )
        .route(
            "/groups/:id/join-result/:member",
            get(get_join_result_inline).post(apply_join_result_endpoint),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let member = "cc".repeat(32);
    let doors = [
        ("POST", format!("/groups/{STABLE}/apply-metadata-event")),
        ("POST", format!("/groups/{STABLE}/join-result/{member}")),
        ("GET", format!("/groups/{STABLE}/join-result/{member}")),
    ];
    for (method, path) in doors {
        for (bearer, refused) in [(session.as_str(), true), ("test-token", false)] {
            let request = Request::builder()
                .method(method)
                .uri(&path)
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{not json"))?;
            let response = app.clone().oneshot(request).await?;
            if refused {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            } else {
                assert_ne!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            }
        }
    }
    Ok(())
}
