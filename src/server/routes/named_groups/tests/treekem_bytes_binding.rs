//! Survivor re-key A1: every TreeKEM seal names its commit bytes and a
//! digest of the event's unsigned fields, so a member that hands the event
//! on cannot swap either. See
//! `docs/adr/transient/T-treekem-bytes-binding-everywhere.md`.
//!
//! The expected bindings are computed here from the published event alone,
//! independently of the production builders.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::epoch_ahead_catchup::{
    catchup_relay_fixture, live_epoch, live_treekem_group, published_removal_event,
    two_member_treekem_group, CatchupRelay,
};
use super::*;

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn empty_extras() -> String {
    digest(&postcard::to_stdvec(&()).expect("postcard"))
}

fn add_extras(
    display_name: Option<&str>,
    key_package_hash: Option<&str>,
    welcome: Option<(&str, u64)>,
) -> String {
    digest(&postcard::to_stdvec(&(display_name, key_package_hash, welcome)).expect("postcard"))
}

fn bytes_binding(epoch: u64, commit: &[u8], extras: &str) -> String {
    format!(
        "treekem:epoch={epoch}:commit={}:extras={extras}",
        digest(commit)
    )
}

fn signed_binding(event: &NamedGroupMetadataEvent) -> String {
    named_group_metadata_event_commit(event)
        .expect("signed commit")
        .security_binding
        .clone()
        .expect("signed binding")
}

/// The TreeKEM epoch and commit bytes a membership event carries.
fn treekem_payload(event: &NamedGroupMetadataEvent) -> (u64, Vec<u8>) {
    let (commit_b64, epoch) = match event {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64,
            treekem_epoch,
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            treekem_commit_b64,
            treekem_epoch,
            ..
        }
        | NamedGroupMetadataEvent::MemberAdded {
            treekem_commit_b64,
            treekem_epoch,
            ..
        }
        | NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_commit_b64,
            treekem_epoch,
            ..
        } => (treekem_commit_b64.clone(), *treekem_epoch),
        other => panic!("not a TreeKEM membership event: {other:?}"),
    };
    let bytes = BASE64
        .decode(commit_b64.expect("TreeKEM commit"))
        .expect("commit base64");
    (epoch.expect("TreeKEM epoch"), bytes)
}

/// The Welcome an add carries, as its content id and length, whichever
/// form the event uses.
fn welcome_identity(
    inline: Option<&String>,
    reference: Option<&WelcomeRef>,
) -> Option<(String, u64)> {
    if let Some(b64) = inline {
        let bytes = BASE64.decode(b64).expect("welcome base64");
        return Some((digest(&bytes), bytes.len() as u64));
    }
    reference.map(|r| (r.welcome_id.clone(), r.byte_len))
}

/// The binding an add must seal, before its recovery suffix.
pub(super) fn expected_add_binding(event: &NamedGroupMetadataEvent) -> String {
    let (epoch, commit) = treekem_payload(event);
    let (display_name, key_package_hash, welcome) = match event {
        NamedGroupMetadataEvent::MemberAdded {
            display_name,
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            ..
        } => (
            display_name.clone(),
            treekem_key_package_hash.clone(),
            welcome_identity(treekem_welcome_b64.as_ref(), welcome_ref.as_ref()),
        ),
        NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_key_package_hash,
            treekem_welcome_b64,
            welcome_ref,
            ..
        } => (
            None,
            treekem_key_package_hash.clone(),
            welcome_identity(treekem_welcome_b64.as_ref(), welcome_ref.as_ref()),
        ),
        other => panic!("not an add: {other:?}"),
    };
    let extras = add_extras(
        display_name.as_deref(),
        key_package_hash.as_deref(),
        welcome.as_ref().map(|(id, len)| (id.as_str(), *len)),
    );
    bytes_binding(epoch, &commit, &extras)
}

/// The binding a removal or a ban must seal.
pub(super) fn expected_removal_binding(event: &NamedGroupMetadataEvent) -> String {
    let (epoch, commit) = treekem_payload(event);
    bytes_binding(epoch, &commit, &empty_extras())
}

fn published_events(state: &AppState) -> Vec<NamedGroupMetadataEvent> {
    state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder")
        .iter()
        .filter_map(|(_, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .collect()
}

fn published_add_of(state: &AppState, member_hex: &str) -> Option<NamedGroupMetadataEvent> {
    published_events(state).into_iter().rev().find(|event| {
        matches!(
            event,
            NamedGroupMetadataEvent::MemberAdded {
                agent_id,
                treekem_commit_b64: Some(_),
                ..
            } if agent_id == member_hex
        )
    })
}

async fn stop(state: &Arc<AppState>) {
    state.shutdown_notify.send_replace(true);
    state.agent.shutdown().await;
}

/// A newcomer's TreeKEM KeyPackage and hex id.
fn newcomer(seed: u8) -> Result<(x0x::identity::AgentId, String, String)> {
    let kp = x0x::identity::AgentKeypair::generate()?;
    let id = kp.agent_id();
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id, &[seed; 32])?;
    Ok((
        id,
        hex::encode(id.as_bytes()),
        BASE64.encode(prepared.key_package_bytes()),
    ))
}

async fn direct_add(
    state: &Arc<AppState>,
    group_id: &str,
    member_hex: &str,
    display_name: &str,
    key_package_b64: &str,
) -> NamedGroupMetadataEvent {
    let response = add_named_group_member(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.to_string()),
        Json(AddNamedGroupMemberRequest {
            agent_id: member_hex.to_string(),
            display_name: Some(display_name.to_string()),
            treekem_key_package_b64: Some(key_package_b64.to_string()),
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await.expect("add response");
    assert_eq!(status, StatusCode::OK, "the admin adds directly: {body}");
    published_add_of(state, member_hex).expect("the add is published")
}

async fn remove_route(state: &Arc<AppState>, group_id: &str, member_hex: &str) -> StatusCode {
    remove_named_group_member(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.to_string(), member_hex.to_string())),
    )
    .await
    .into_response()
    .status()
}

#[tokio::test]
async fn admin_removal_seals_the_digest_binding() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    assert_eq!(
        remove_route(&fixture.state, &fixture.group_id, &member_hex).await,
        StatusCode::OK
    );
    let removal = published_removal_event(&fixture.state).expect("published removal");
    let binding = signed_binding(&removal);
    assert_eq!(
        binding,
        expected_removal_binding(&removal),
        "the removal must name its TreeKEM bytes and the empty extras"
    );
    let stored = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .and_then(|info| info.security_binding.clone());
    assert_eq!(stored.as_deref(), Some(binding.as_str()));
    stop(&fixture.state).await;
    Ok(())
}

/// The direct add and the join approval both keep the recovery record's
/// suffix after the digest, and the authority's attested recovery record
/// still verifies against the new binding.
#[tokio::test]
async fn an_add_keeps_its_recovery_suffix_after_the_digest() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;

    let (_, mom_hex, mom_package) = newcomer(0x31)?;
    let added = direct_add(state, group_id, &mom_hex, "Mom", &mom_package).await;
    let binding = signed_binding(&added);
    let (bytes_part, suffix) = binding.split_once(';').expect("recovery suffix");
    assert_eq!(bytes_part, expected_add_binding(&added));
    assert!(
        suffix.starts_with("member-recovery=") && !suffix.contains(';'),
        "one recovery suffix after the digest, got {binding}"
    );
    let recovery = state
        .treekem_member_key_packages
        .events_matching(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if *member_agent_id == mom_hex
            )
        })
        .await
        .into_iter()
        .next()
        .expect("attested recovery record");
    let info = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group");
    assert!(
        verify_authority_attested_member_joined_recovery(&info, &recovery),
        "the recovery record must verify against the digest binding"
    );

    let (_, requester_hex, requester_package) = newcomer(0x32)?;
    let request_id = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_id).expect("group");
        let mut request = x0x::groups::JoinRequest::new(
            group_id.clone(),
            requester_hex.clone(),
            None,
            now_millis_u64(),
        );
        request.treekem_key_package_b64 = Some(requester_package);
        let request_id = request.request_id.clone();
        info.join_requests.insert(request_id.clone(), request);
        info.recompute_state_hash();
        request_id
    };
    let response = approve_join_request(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_id.clone(), request_id)),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "the admin approves: {body}");
    let approved = published_events(state)
        .into_iter()
        .rev()
        .find(|event| matches!(event, NamedGroupMetadataEvent::JoinRequestApproved { .. }))
        .expect("published approval");
    let binding = signed_binding(&approved);
    let (bytes_part, suffix) = binding.split_once(';').expect("recovery suffix");
    assert_eq!(bytes_part, expected_add_binding(&approved));
    assert!(suffix.starts_with("member-recovery="), "got {binding}");
    stop(state).await;
    Ok(())
}

/// X adds "Mom". A copy whose name was changed on the way is refused, and
/// S's roster shows the name X signed for. Until A3 a third party's add is
/// refused for its sender alone, so the changed copy arrives as X's.
#[tokio::test]
async fn a_relayed_add_cannot_rename_the_new_member() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let admin = &cast.fixture.state;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let admin_id = admin.agent.agent_id();
    let (_, mom_hex, mom_package) = newcomer(0x41)?;
    let genuine = direct_add(admin, group_id, &mom_hex, "Mom", &mom_package).await;

    let mut renamed = genuine.clone();
    if let NamedGroupMetadataEvent::MemberAdded { display_name, .. } = &mut renamed {
        *display_name = Some("Mallory".to_string());
    }
    let refused = apply_named_group_metadata_event(victim, renamed, admin_id, true, None).await;
    assert!(
        !refused.accepted,
        "a renamed copy must be refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(victim, group_id).await,
        cast.epoch_before,
        "the refused copy installs nothing"
    );

    let installed = apply_named_group_metadata_event(victim, genuine, admin_id, true, None).await;
    assert!(installed.accepted, "the signed add installs: {installed:?}");
    let name = victim
        .named_groups
        .read()
        .await
        .get(group_id)
        .and_then(|info| info.members_v2.get(&mom_hex).cloned())
        .and_then(|member| member.display_name);
    assert_eq!(name.as_deref(), Some("Mom"));
    cast.shutdown().await;
    Ok(())
}

/// Promote the victim to admin on both rosters, so it may remove members.
async fn promote_victim(cast: &CatchupRelay) {
    let victim_hex = hex::encode(cast.victim_state.agent.agent_id().as_bytes());
    let promoted = {
        let mut groups = cast.fixture.state.named_groups.write().await;
        let info = groups.get_mut(&cast.fixture.group_id).expect("group");
        info.set_member_role(&victim_hex, x0x::groups::GroupRole::Admin);
        info.recompute_state_hash();
        info.clone()
    };
    cast.victim_state
        .named_groups
        .write()
        .await
        .insert(cast.fixture.group_id.clone(), promoted);
}

/// The copy carries another KeyPackage hash: refused. S keeps the hash X
/// signed for, so S can later remove that member with its real package.
#[tokio::test]
async fn a_relayed_add_cannot_swap_its_key_package_hash() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    promote_victim(&cast).await;
    let admin = &cast.fixture.state;
    let victim = &cast.victim_state;
    let group_id = &cast.fixture.group_id;
    let admin_id = admin.agent.agent_id();
    let (_, mom_hex, mom_package) = newcomer(0x51)?;
    let genuine = direct_add(admin, group_id, &mom_hex, "Mom", &mom_package).await;

    let mut swapped = genuine.clone();
    if let NamedGroupMetadataEvent::MemberAdded {
        treekem_key_package_hash,
        ..
    } = &mut swapped
    {
        *treekem_key_package_hash = Some(digest(b"another key package"));
    }
    let refused = apply_named_group_metadata_event(victim, swapped, admin_id, true, None).await;
    assert!(
        !refused.accepted,
        "a copy with another key-package hash must be refused: {refused:?}"
    );
    let installed = apply_named_group_metadata_event(victim, genuine, admin_id, true, None).await;
    assert!(installed.accepted, "the signed add installs: {installed:?}");

    // The authority hands every member the KeyPackage as its attested
    // recovery record.
    let recovery = admin
        .treekem_member_key_packages
        .events_matching(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if *member_agent_id == mom_hex
            )
        })
        .await
        .into_iter()
        .next()
        .expect("attested recovery record");
    cache_treekem_member_key_package(victim, join_result_key(group_id, &mom_hex), recovery, true)
        .await;
    let epoch = live_epoch(victim, group_id).await;
    assert_eq!(
        remove_route(victim, group_id, &mom_hex).await,
        StatusCode::OK,
        "S removes the member with the package X signed for"
    );
    assert_eq!(live_epoch(victim, group_id).await, epoch + 1);
    cast.shutdown().await;
    Ok(())
}

/// The seal fails after the tree was mutated. The live tree, the snapshot
/// on disk and the roster are as they were, nothing was published, and the
/// rolled-back tree still takes the next removal.
#[tokio::test]
async fn seal_failure_installs_nothing() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let state = &fixture.state;
    let group_id = &fixture.group_id;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let info_before = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group");
    {
        let group = live_treekem_group(state, group_id).await;
        let guard = group.lock().await;
        persist_treekem_and_named_groups_atomic_with_info(
            state,
            group_id,
            info_before.clone(),
            &guard,
        )
        .await?;
    }
    let snapshot_path = treekem_snapshot_path(&state.treekem_dir, group_id);
    let snapshot_before = tokio::fs::read(&snapshot_path).await?;
    let epoch_before = live_epoch(state, group_id).await;
    state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder")
        .clear();

    state
        .named_group_test_recorders
        .seal_force_err
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let failed = remove_route(state, group_id, &member_hex).await;
    assert_ne!(failed, StatusCode::OK, "the forced seal failure refuses");
    assert!(
        !state
            .named_group_test_recorders
            .seal_force_err
            .load(std::sync::atomic::Ordering::SeqCst),
        "the removal reached the seal"
    );
    {
        let group = live_treekem_group(state, group_id).await;
        assert_eq!(
            group.lock().await.epoch(),
            epoch_before,
            "the live tree is rolled back"
        );
    }
    assert_eq!(
        tokio::fs::read(&snapshot_path).await?,
        snapshot_before,
        "the persisted snapshot is unchanged"
    );
    let info_after = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group");
    assert_eq!(info_after.state_hash, info_before.state_hash);
    assert!(info_after.has_active_member(&member_hex));
    assert!(published_events(state).is_empty(), "no event is published");

    assert_eq!(
        remove_route(state, group_id, &member_hex).await,
        StatusCode::OK,
        "the rolled-back tree takes the next removal"
    );
    assert_eq!(live_epoch(state, group_id).await, epoch_before + 1);
    stop(state).await;
    Ok(())
}
