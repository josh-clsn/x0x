//! Survivor re-key A3: any member hands on any signed, commit-bearing event,
//! and it applies as its verified signer. Nothing the deliverer controls is
//! applied. See `docs/adr/transient/T-any-member-delivers-signed-commits.md`.
//!
//! The owner acts through its real routes. S2 applies what the owner
//! publishes. S1 was away, and gets each event from S2 alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::committer_leaf::victim_holds_the_admin_by_hash;
use super::epoch_ahead_catchup::{
    catchup_relay_fixture, deliver_catchup, encrypt, legacy_bound_removal, live_epoch,
    live_treekem_group, published_removal_event, roster_head, survivor_relay_fixture,
    swap_treekem_commit, two_member_treekem_group, wait_until, CatchupRelay, SurvivorRelay,
};
use super::*;

pub(super) fn owner_extension() -> axum::extract::Extension<crate::server::rider_auth::ActorContext>
{
    axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
}

pub(super) fn hex_id(id: &x0x::identity::AgentId) -> String {
    hex::encode(id.as_bytes())
}

/// The last event `state` published that `pick` accepts.
pub(super) fn published(
    state: &AppState,
    pick: impl Fn(&NamedGroupMetadataEvent) -> bool,
) -> Option<NamedGroupMetadataEvent> {
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder");
    published
        .iter()
        .rev()
        .filter_map(|(_, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find(|event| pick(event))
}

pub(super) async fn roster(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group")
}

pub(super) async fn assert_ok(response: axum::response::Response, what: &str) {
    let (status, body) = response_json(response).await.expect("route response");
    assert_eq!(status, StatusCode::OK, "{what}: {body}");
}

pub(super) async fn ban_route(state: &Arc<AppState>, group_id: &str, member_hex: &str) {
    let response = ban_group_member(
        State(Arc::clone(state)),
        owner_extension(),
        Path((group_id.to_string(), member_hex.to_string())),
    )
    .await
    .into_response();
    assert_ok(response, "the owner bans").await;
}

pub(super) async fn unban_route(state: &Arc<AppState>, group_id: &str, member_hex: &str) {
    let response = unban_group_member(
        State(Arc::clone(state)),
        owner_extension(),
        Path((group_id.to_string(), member_hex.to_string())),
    )
    .await
    .into_response();
    assert_ok(response, "the owner unbans").await;
}

pub(super) async fn rename_route(state: &Arc<AppState>, group_id: &str, name: &str) {
    let response = update_named_group(
        State(Arc::clone(state)),
        owner_extension(),
        Path(group_id.to_string()),
        Json(UpdateGroupRequest {
            name: Some(name.to_string()),
            description: None,
        }),
    )
    .await
    .into_response();
    assert_ok(response, "the owner renames").await;
}

pub(super) async fn admission_route(state: &Arc<AppState>, group_id: &str) {
    let response = update_group_policy(
        State(Arc::clone(state)),
        owner_extension(),
        Path(group_id.to_string()),
        Json(UpdateGroupPolicyRequest {
            preset: None,
            discoverability: None,
            admission: Some(x0x::groups::GroupAdmission::RequestAccess),
            confidentiality: None,
            read_access: None,
            write_access: None,
        }),
    )
    .await
    .into_response();
    assert_ok(response, "the owner changes the policy").await;
}

pub(super) async fn role_route(
    state: &Arc<AppState>,
    group_id: &str,
    member_hex: &str,
    role: &str,
) {
    let response = update_member_role(
        State(Arc::clone(state)),
        owner_extension(),
        Path((group_id.to_string(), member_hex.to_string())),
        Json(UpdateMemberRoleRequest {
            role: role.to_string(),
        }),
    )
    .await
    .into_response();
    assert_ok(response, "the owner changes a role").await;
}

/// A newcomer's id and its TreeKEM KeyPackage, prepared from `seed`.
pub(super) fn newcomer(seed: u8) -> Result<(x0x::identity::AgentId, String)> {
    let id = x0x::identity::AgentKeypair::generate()?.agent_id();
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id, &[seed; 32])?;
    Ok((id, BASE64.encode(prepared.key_package_bytes())))
}

pub(super) async fn direct_add_route(
    state: &Arc<AppState>,
    group_id: &str,
    member_hex: &str,
    display_name: &str,
    key_package_b64: &str,
) -> NamedGroupMetadataEvent {
    let response = add_named_group_member(
        State(Arc::clone(state)),
        owner_extension(),
        Path(group_id.to_string()),
        Json(AddNamedGroupMemberRequest {
            agent_id: member_hex.to_string(),
            display_name: Some(display_name.to_string()),
            treekem_key_package_b64: Some(key_package_b64.to_string()),
        }),
    )
    .await
    .into_response();
    assert_ok(response, "the owner adds").await;
    published(state, |event| {
        matches!(
            event,
            NamedGroupMetadataEvent::MemberAdded {
                agent_id,
                treekem_commit_b64: Some(_),
                ..
            } if agent_id == member_hex
        )
    })
    .expect("the add is published")
}

/// S2 applies `event` from its author, the owner.
pub(super) async fn s2_applies(cast: &SurvivorRelay, event: &NamedGroupMetadataEvent) {
    let owner_id = cast.fixture.state.agent.agent_id();
    let applied =
        apply_named_group_metadata_event(&cast.s2, event.clone(), owner_id, true, None).await;
    assert!(
        applied.accepted,
        "S2 applies the owner's event: {applied:?}"
    );
}

/// S1 gets `event` by catch-up from S2 alone.
pub(super) async fn s2_serves_s1(cast: &SurvivorRelay, event: NamedGroupMetadataEvent) {
    let s2_id = cast.s2.agent.agent_id();
    deliver_catchup(&cast.s1, &s2_id, &cast.fixture.group_id, event).await;
}

/// S1 holds the owner's head and epoch, reads the owner's next message, and
/// the removed member R does not.
pub(super) async fn s1_follows_the_owner(cast: &mut SurvivorRelay, text: &[u8]) -> Result<()> {
    let owner = &cast.fixture.state;
    let group_id = &cast.fixture.group_id;
    assert_eq!(
        live_epoch(&cast.s1, group_id).await,
        live_epoch(owner, group_id).await,
        "S1 reaches the owner's epoch"
    );
    let r_hex = hex_id(&cast.fixture.member_id);
    assert_eq!(
        roster_head(&cast.s1, group_id, &r_hex).await,
        roster_head(owner, group_id, &r_hex).await,
        "S1's roster is the owner's"
    );
    let ciphertext = encrypt(owner, group_id, text).await?;
    let opened = {
        let group = live_treekem_group(&cast.s1, group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, text);
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "R must not read it"
    );
    Ok(())
}

#[tokio::test]
async fn a_survivor_delivers_a_ban() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let r_hex = hex_id(&cast.fixture.member_id);
    let epoch_before = live_epoch(&cast.s1, &group_id).await;

    ban_route(&owner, &group_id, &r_hex).await;
    let ban = published(&owner, |event| {
        matches!(
            event,
            NamedGroupMetadataEvent::MemberBanned {
                treekem_commit_b64: Some(_),
                ..
            }
        )
    })
    .expect("the ban is published");
    s2_applies(&cast, &ban).await;
    assert_eq!(live_epoch(&cast.s1, &group_id).await, epoch_before);

    s2_serves_s1(&cast, ban).await;
    assert!(
        roster(&cast.s1, &group_id).await.is_banned(&r_hex),
        "S1 holds the ban S2 handed on"
    );
    s1_follows_the_owner(&mut cast, b"after the ban").await?;
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_survivor_delivers_an_add() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let (nan, nan_package) = newcomer(0x61)?;
    let nan_hex = hex_id(&nan);

    let added = direct_add_route(&owner, &group_id, &nan_hex, "Nan", &nan_package).await;
    s2_applies(&cast, &added).await;
    s2_serves_s1(&cast, added).await;

    let seat = roster(&cast.s1, &group_id)
        .await
        .members_v2
        .get(&nan_hex)
        .cloned()
        .expect("S1 seats the newcomer");
    assert!(seat.is_active());
    assert_eq!(seat.display_name.as_deref(), Some("Nan"), "the signed name");
    assert_eq!(
        seat.treekem_key_package_hash.as_deref(),
        Some(blake3::hash(nan_package.as_bytes()).to_hex().as_str()),
        "the signed KeyPackage hash"
    );
    assert_eq!(
        roster_head(&cast.s1, &group_id, &nan_hex).await,
        roster_head(&owner, &group_id, &nan_hex).await
    );
    s1_follows_the_owner(&mut cast, b"after the add").await?;
    cast.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_survivor_delivers_a_rename_policy_role_and_unban() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let r_hex = hex_id(&cast.fixture.member_id);
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    let is_ban = |event: &NamedGroupMetadataEvent| {
        matches!(event, NamedGroupMetadataEvent::MemberBanned { .. })
    };

    let mut events = Vec::new();
    ban_route(&owner, &group_id, &r_hex).await;
    events.push(published(&owner, is_ban).expect("ban"));
    rename_route(&owner, &group_id, "Family").await;
    events.push(
        published(&owner, |event| {
            matches!(event, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
        })
        .expect("rename"),
    );
    admission_route(&owner, &group_id).await;
    events.push(
        published(&owner, |event| {
            matches!(event, NamedGroupMetadataEvent::PolicyUpdated { .. })
        })
        .expect("policy"),
    );
    role_route(&owner, &group_id, &s2_hex, "admin").await;
    events.push(
        published(&owner, |event| {
            matches!(event, NamedGroupMetadataEvent::MemberRoleUpdated { .. })
        })
        .expect("role"),
    );
    unban_route(&owner, &group_id, &r_hex).await;
    events.push(
        published(&owner, |event| {
            matches!(event, NamedGroupMetadataEvent::MemberUnbanned { .. })
        })
        .expect("unban"),
    );

    for event in &events {
        s2_applies(&cast, event).await;
    }
    for event in events {
        let kind = named_group_metadata_event_kind(&event);
        let before = roster(&cast.s1, &group_id).await.state_revision;
        s2_serves_s1(&cast, event).await;
        assert_eq!(
            roster(&cast.s1, &group_id).await.state_revision,
            before + 1,
            "S1 applies the {kind} S2 handed on"
        );
    }

    let s1 = roster(&cast.s1, &group_id).await;
    assert_eq!(s1.name, "Family");
    assert_eq!(
        s1.policy.admission,
        x0x::groups::GroupAdmission::RequestAccess
    );
    assert_eq!(s1.caller_role(&s2_hex), Some(x0x::groups::GroupRole::Admin));
    assert!(!s1.is_banned(&r_hex), "the unban landed");
    s1_follows_the_owner(&mut cast, b"after the unban").await?;
    cast.shutdown().await;
    Ok(())
}

/// `owner`'s add of `member` as a daemon from before survivor re-key A1
/// sealed it: `treekem:epoch=<n>`, which names neither the bytes nor the
/// fields. The Welcome is inline.
async fn legacy_bound_add(
    owner: &AppState,
    group_id: &str,
    member: x0x::identity::AgentId,
    package_b64: &str,
) -> Result<NamedGroupMetadataEvent> {
    let owner_hex = hex_id(&owner.agent.agent_id());
    let member_hex = hex_id(&member);
    let package_hash = blake3::hash(package_b64.as_bytes()).to_hex().to_string();
    let added = {
        let group = live_treekem_group(owner, group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(member, &BASE64.decode(package_b64)?)?
    };
    let epoch = live_epoch(owner, group_id).await;
    let mut next = roster(owner, group_id).await;
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(owner_hex.clone()),
        Some("Nan".to_string()),
    );
    next.set_member_treekem_key_package_hash(&member_hex, package_hash.clone());
    next.secret_epoch = epoch;
    next.security_binding = Some(format!("treekem:epoch={epoch}"));
    let commit = next.seal_commit(owner.agent.identity().agent_keypair(), now_millis_u64())?;
    owner
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), next);
    Ok(NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision,
        actor: owner_hex,
        agent_id: member_hex,
        display_name: Some("Nan".to_string()),
        treekem_commit_b64: Some(BASE64.encode(&added.commit)),
        treekem_welcome_b64: Some(BASE64.encode(&added.welcome)),
        welcome_ref: None,
        treekem_epoch: Some(epoch),
        treekem_key_package_hash: Some(package_hash),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        roster_certificates_b64: Vec::new(),
        commit: Some(commit),
    })
}

#[tokio::test]
async fn a_legacy_bound_add_from_a_non_author_is_refused() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let owner_id = cast.fixture.state.agent.agent_id();
    let epoch_before = live_epoch(&cast.s1, &group_id).await;
    let (nan, nan_package) = newcomer(0x62)?;
    let nan_hex = hex_id(&nan);
    let legacy = legacy_bound_add(&cast.fixture.state, &group_id, nan, &nan_package).await?;

    s2_serves_s1(&cast, legacy.clone()).await;
    assert_eq!(
        live_epoch(&cast.s1, &group_id).await,
        epoch_before,
        "a legacy add from a non-author installs nothing"
    );
    assert!(!roster(&cast.s1, &group_id)
        .await
        .has_active_member(&nan_hex));

    deliver_catchup(&cast.s1, &owner_id, &group_id, legacy).await;
    assert!(
        roster(&cast.s1, &group_id)
            .await
            .has_active_member(&nan_hex),
        "its verified author still delivers it"
    );
    s1_follows_the_owner(&mut cast, b"after the legacy add").await?;
    cast.shutdown().await;
    Ok(())
}

fn with_actor(event: &NamedGroupMetadataEvent, forged: &str) -> NamedGroupMetadataEvent {
    let mut forged_event = event.clone();
    match &mut forged_event {
        NamedGroupMetadataEvent::GroupMetadataUpdated { actor, .. }
        | NamedGroupMetadataEvent::MemberBanned { actor, .. } => *actor = forged.to_string(),
        other => panic!("not a forgeable test event: {other:?}"),
    }
    forged_event
}

/// The signature decides, never the `actor` field. S2 is an admin, so a
/// copy naming S2 as the actor of the owner's commit would once have
/// applied from S2. It authorises nothing, whoever delivers it.
#[tokio::test]
async fn a_forged_actor_field_authorises_nothing() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let owner_id = owner.agent.agent_id();
    let group_id = cast.fixture.group_id.clone();
    let s2_id = cast.s2.agent.agent_id();
    let s2_hex = hex_id(&s2_id);
    let r_hex = hex_id(&cast.fixture.member_id);

    role_route(&owner, &group_id, &s2_hex, "admin").await;
    let promotion = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::MemberRoleUpdated { .. })
    })
    .expect("promotion");
    for state in [&cast.s1, &cast.s2] {
        let applied =
            apply_named_group_metadata_event(state, promotion.clone(), owner_id, true, None).await;
        assert!(applied.accepted, "{applied:?}");
    }

    rename_route(&owner, &group_id, "Family").await;
    let rename = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("rename");
    let forged = with_actor(&rename, &s2_hex);
    let head_before = roster_head(&cast.s1, &group_id, &r_hex).await;
    for deliverer in [s2_id, owner_id] {
        deliver_catchup(&cast.s1, &deliverer, &group_id, forged.clone()).await;
        assert_eq!(
            roster_head(&cast.s1, &group_id, &r_hex).await,
            head_before,
            "a forged actor applies nothing"
        );
        assert_ne!(roster(&cast.s1, &group_id).await.name, "Family");
    }
    s2_serves_s1(&cast, rename).await;
    assert_eq!(roster(&cast.s1, &group_id).await.name, "Family");

    ban_route(&owner, &group_id, &r_hex).await;
    let ban = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::MemberBanned { .. })
    })
    .expect("ban");
    let epoch_before = live_epoch(&cast.s1, &group_id).await;
    s2_serves_s1(&cast, with_actor(&ban, &s2_hex)).await;
    assert_eq!(live_epoch(&cast.s1, &group_id).await, epoch_before);
    assert!(roster(&cast.s1, &group_id).await.has_active_member(&r_hex));
    s2_serves_s1(&cast, ban).await;
    s1_follows_the_owner(&mut cast, b"after the genuine ban").await?;
    cast.shutdown().await;
    Ok(())
}

async fn post_metadata_door(
    state: &Arc<AppState>,
    group_id: &str,
    event: &NamedGroupMetadataEvent,
    claimed_sender: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = apply_group_metadata_event(
        State(Arc::clone(state)),
        owner_extension(),
        Path(group_id.to_string()),
        Json(ApplyMetadataEventRequest {
            event_b64: BASE64.encode(serde_json::to_vec(event)?),
            sender_agent_id: claimed_sender.to_string(),
        }),
    )
    .await
    .into_response();
    response_json(response).await
}

/// The join-request lifecycle stays with its author: S2 cannot hand on the
/// owner's rejection, and neither can the engine-A door, whose sender is
/// only claimed. The owner's own copy applies.
#[tokio::test]
async fn join_request_lifecycle_stays_author_only() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let owner_id = owner.agent.agent_id();
    let owner_hex = hex_id(&owner_id);
    let group_id = cast.fixture.group_id.clone();
    let (requester, _) = newcomer(0x63)?;
    let request =
        x0x::groups::JoinRequest::new(group_id.clone(), hex_id(&requester), None, now_millis_u64());
    let request_id = request.request_id.clone();
    for state in [&owner, &cast.s1, &cast.s2] {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        info.join_requests
            .insert(request_id.clone(), request.clone());
    }
    let response = reject_join_request(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), request_id.clone())),
    )
    .await
    .into_response();
    assert_ok(response, "the owner rejects").await;
    let rejected = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::JoinRequestRejected { .. })
    })
    .expect("the rejection is published");
    let pending = |info: x0x::groups::GroupInfo| info.join_requests[&request_id].is_pending();

    s2_serves_s1(&cast, rejected.clone()).await;
    assert!(
        pending(roster(&cast.s1, &group_id).await),
        "S2 cannot hand on the owner's rejection"
    );
    let (status, body) = post_metadata_door(&cast.s1, &group_id, &rejected, &owner_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(pending(roster(&cast.s1, &group_id).await));

    deliver_catchup(&cast.s1, &owner_id, &group_id, rejected).await;
    assert!(
        !pending(roster(&cast.s1, &group_id).await),
        "the author's own copy applies"
    );
    cast.shutdown().await;
    Ok(())
}

/// Three daemons on the shared-secret plane (no TreeKEM bytes, so no
/// binding over an add's fields): the owner, the deliverer and S1.
struct GssGroup {
    owner: Arc<AppState>,
    s2: Arc<AppState>,
    s1: Arc<AppState>,
    group_id: String,
    _dirs: Vec<tempfile::TempDir>,
}

async fn gss_group() -> Result<GssGroup> {
    let (owner, owner_dir) = secure_endpoint_test_state().await?;
    let (s2, s2_dir) = secure_endpoint_test_state().await?;
    let (s1, s1_dir) = secure_endpoint_test_state().await?;
    let group_id = "5e".repeat(16);
    let owner_hex = hex_id(&owner.agent.agent_id());
    let mut info = x0x::groups::GroupInfo::new(
        "gss".to_string(),
        String::new(),
        owner.agent.agent_id(),
        group_id.clone(),
    );
    assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::Gss);
    for state in [&s2, &s1] {
        info.add_member(
            hex_id(&state.agent.agent_id()),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
    }
    info.recompute_state_hash();
    for state in [&owner, &s2, &s1] {
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
    }
    Ok(GssGroup {
        owner,
        s2,
        s1,
        group_id,
        _dirs: vec![owner_dir, s2_dir, s1_dir],
    })
}

/// F-2. On the shared-secret plane nothing binds an add's display name or
/// KeyPackage hash, so a copy its author did not deliver applies without
/// them. No copy moves an unsigned revision counter by more than one step.
#[tokio::test]
async fn a_non_author_copy_applies_no_unbound_field() -> Result<()> {
    let cast = gss_group().await?;
    let owner_hex = hex_id(&cast.owner.agent.agent_id());
    let owner_id = cast.owner.agent.agent_id();
    let s2_id = cast.s2.agent.agent_id();
    let group_id = cast.group_id.clone();
    let (mom, _) = newcomer(0x64)?;
    let mom_hex = hex_id(&mom);

    let mut next = roster(&cast.owner, &group_id).await;
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.add_member(
        mom_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(owner_hex.clone()),
        Some("Mom".to_string()),
    );
    let commit = next.seal_commit(
        cast.owner.agent.identity().agent_keypair(),
        now_millis_u64(),
    )?;
    cast.owner
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), next);
    let added = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.clone(),
        revision: u64::MAX,
        actor: owner_hex.clone(),
        agent_id: mom_hex.clone(),
        display_name: Some("Mom".to_string()),
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: Some("ab".repeat(32)),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        roster_certificates_b64: Vec::new(),
        commit: Some(commit),
    };

    let roster_revision_before = roster(&cast.s1, &group_id).await.roster_revision;
    deliver_catchup(&cast.s1, &s2_id, &group_id, added.clone()).await;
    let s1 = roster(&cast.s1, &group_id).await;
    let seat = s1
        .members_v2
        .get(&mom_hex)
        .cloned()
        .expect("S1 applies the signed add from S2");
    assert!(seat.is_active());
    assert_eq!(seat.display_name, None, "no unsigned name from a deliverer");
    assert_eq!(seat.treekem_key_package_hash, None);
    assert_eq!(s1.roster_revision, roster_revision_before + 1);

    deliver_catchup(&cast.s2, &owner_id, &group_id, added).await;
    assert_eq!(
        roster(&cast.s2, &group_id).await.members_v2[&mom_hex]
            .display_name
            .as_deref(),
        Some("Mom"),
        "the author's own copy keeps its name"
    );

    let mut next = roster(&cast.owner, &group_id).await;
    let mut policy = next.policy.clone();
    policy.admission = x0x::groups::GroupAdmission::RequestAccess;
    next.policy = policy.clone();
    let commit = next.seal_commit(
        cast.owner.agent.identity().agent_keypair(),
        now_millis_u64(),
    )?;
    let policy_update = NamedGroupMetadataEvent::PolicyUpdated {
        group_id: group_id.clone(),
        revision: u64::MAX,
        actor: owner_hex,
        policy,
        commit: Some(commit),
    };
    let policy_revision_before = roster(&cast.s1, &group_id).await.policy_revision;
    deliver_catchup(&cast.s1, &s2_id, &group_id, policy_update).await;
    let s1 = roster(&cast.s1, &group_id).await;
    assert_eq!(
        s1.policy.admission,
        x0x::groups::GroupAdmission::RequestAccess
    );
    assert_eq!(s1.policy_revision, policy_revision_before + 1);
    for state in [&cast.owner, &cast.s2, &cast.s1] {
        state.shutdown_notify.send_replace(true);
        state.agent.shutdown().await;
    }
    Ok(())
}

/// A1 review I-1: the engine-A door's sender is a claim. A legacy-bound
/// removal through it is refused even when it claims the author.
#[tokio::test]
async fn the_engine_a_metadata_door_refuses_unnamed_bytes_whatever_it_claims() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin_hex = hex_id(&cast.fixture.state.agent.agent_id());
    let legacy = legacy_bound_removal(&cast.fixture).await?;
    let (status, body) =
        post_metadata_door(&cast.victim_state, &group_id, &legacy, &admin_hex).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        live_epoch(&cast.victim_state, &group_id).await,
        cast.epoch_before
    );
    cast.shutdown().await;
    Ok(())
}

/// A1 review I-1: a removal that names its bytes applies through the door
/// as its signer, whatever sender the caller claims.
#[tokio::test]
async fn the_engine_a_metadata_door_applies_named_bytes_as_their_signer() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let member_hex = hex_id(&cast.fixture.member_id);
    let response = remove_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        owner_extension(),
        Path((group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let genuine = published_removal_event(&cast.fixture.state).expect("removal");
    let liar = hex_id(&cast.member_b);
    let (status, body) = post_metadata_door(&cast.victim_state, &group_id, &genuine, &liar).await?;
    assert_eq!(status, StatusCode::OK, "applied as its signer: {body}");
    victim_reads_the_admin(&mut cast, b"through the door").await?;
    cast.shutdown().await;
    Ok(())
}

async fn victim_reads_the_admin(cast: &mut CatchupRelay, text: &[u8]) -> Result<()> {
    let group_id = &cast.fixture.group_id;
    assert_eq!(
        live_epoch(&cast.victim_state, group_id).await,
        live_epoch(&cast.fixture.state, group_id).await
    );
    let ciphertext = encrypt(&cast.fixture.state, group_id, text).await?;
    let opened = {
        let group = live_treekem_group(&cast.victim_state, group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(opened, text);
    assert!(cast
        .fixture
        .leaver_group
        .decrypt_message(&ciphertext)
        .is_err());
    Ok(())
}

/// A joiner's roster before its Welcome: the authority's, every seat held
/// by its committed hash alone.
fn hash_only_stub(info: &x0x::groups::GroupInfo) -> x0x::groups::GroupInfo {
    let mut stub = info.clone();
    for seat in stub.members_v2.values_mut() {
        seat.treekem_key_package_b64 = None;
    }
    stub
}

/// The joiner's own TreeKEM KeyPackage, prepared from its agent seed as
/// its Welcome install will.
fn own_package(state: &AppState, group_id: &str) -> Result<String> {
    let seed = agent_treekem_seed(state.agent.as_ref(), &hex::decode(group_id)?);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &seed)?;
    Ok(BASE64.encode(prepared.key_package_bytes()))
}

/// The Welcome a published add names, inlined from the authority's store.
async fn inline_welcome(authority: &AppState, event: &mut NamedGroupMetadataEvent) {
    let welcome_id = match &*event {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(reference),
            ..
        }
        | NamedGroupMetadataEvent::JoinRequestApproved {
            welcome_ref: Some(reference),
            ..
        } => reference.welcome_id.clone(),
        other => panic!("no welcome reference: {other:?}"),
    };
    let bytes = authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .map(|pending| pending.bytes.clone())
        .expect("staged welcome");
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            treekem_welcome_b64,
            ..
        }
        | NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_welcome_b64,
            ..
        } => *treekem_welcome_b64 = Some(BASE64.encode(bytes)),
        _ => unreachable!(),
    }
}

/// A joiner that knows the owner's group by its stub and expects the
/// owner's join result.
async fn joiner_expecting(
    owner: &AppState,
    group_id: &str,
) -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let (joiner, dir) = secure_endpoint_test_state().await?;
    let joiner_hex = hex_id(&joiner.agent.agent_id());
    joiner.named_groups.write().await.insert(
        group_id.to_string(),
        hash_only_stub(&roster(owner, group_id).await),
    );
    record_expected_join_result_inviter(
        &joiner,
        join_result_key(group_id, &joiner_hex),
        hex_id(&owner.agent.agent_id()),
    );
    Ok((joiner, dir))
}

async fn post_join_result_door(
    joiner: &Arc<AppState>,
    group_id: &str,
    event: &NamedGroupMetadataEvent,
    claimed_sender: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = apply_join_result_endpoint(
        State(Arc::clone(joiner)),
        owner_extension(),
        Path((group_id.to_string(), hex_id(&joiner.agent.agent_id()))),
        Json(ApplyJoinResultRequest {
            event_b64: BASE64.encode(serde_json::to_vec(event)?),
            sender_agent_id: claimed_sender.to_string(),
        }),
    )
    .await
    .into_response();
    response_json(response).await
}

/// A1 review I-1, the other door: a relayed join result whose binding
/// names no bytes is refused, though it claims the expected inviter.
#[tokio::test]
async fn the_engine_a_join_result_door_refuses_unnamed_bytes_whatever_it_claims() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let owner = Arc::clone(&fixture.state);
    let group_id = fixture.group_id.clone();
    let (joiner, joiner_dir) = joiner_expecting(&owner, &group_id).await?;
    let package = own_package(&joiner, &group_id)?;
    let legacy = legacy_bound_add(&owner, &group_id, joiner.agent.agent_id(), &package).await?;
    let owner_hex = hex_id(&owner.agent.agent_id());
    let (status, body) = post_join_result_door(&joiner, &group_id, &legacy, &owner_hex).await?;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(!joiner.treekem_groups.read().await.contains_key(&group_id));
    for state in [&joiner, &owner] {
        state.shutdown_notify.send_replace(true);
        state.agent.shutdown().await;
    }
    drop(joiner_dir);
    Ok(())
}

/// A1 review I-1, the other door: the expected inviter's join result that
/// names its bytes applies as its signer, whatever sender the caller claims.
#[tokio::test]
async fn the_engine_a_join_result_door_applies_as_the_signer() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let owner = Arc::clone(&fixture.state);
    let group_id = fixture.group_id.clone();
    let (joiner, joiner_dir) = joiner_expecting(&owner, &group_id).await?;
    let joiner_hex = hex_id(&joiner.agent.agent_id());
    let package = own_package(&joiner, &group_id)?;
    let mut added = direct_add_route(&owner, &group_id, &joiner_hex, "Jo", &package).await;
    inline_welcome(&owner, &mut added).await;
    let liar = hex_id(&fixture.member_id);
    let (status, body) = post_join_result_door(&joiner, &group_id, &added, &liar).await?;
    assert_eq!(status, StatusCode::OK, "applied as its signer: {body}");
    assert_eq!(
        live_epoch(&joiner, &group_id).await,
        live_epoch(&owner, &group_id).await
    );
    for state in [&joiner, &owner] {
        state.shutdown_notify.send_replace(true);
        state.agent.shutdown().await;
    }
    drop(joiner_dir);
    Ok(())
}

/// A2 review m-1: a legacy binding names no bytes, so the owner's own
/// commit at the same epoch that removes someone else (S2) would pass
/// every other check as its removal of R. The removal must leave R with no
/// leaf: refused, and rolled back.
#[tokio::test]
async fn a_removal_whose_commit_keeps_the_target_is_refused() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let owner_id = owner.agent.agent_id();
    let group_id = cast.fixture.group_id.clone();
    let s2_id = cast.s2.agent.agent_id();
    let s2_package = BASE64.decode(
        roster(&owner, &group_id).await.members_v2[&hex_id(&s2_id)]
            .treekem_key_package_b64
            .clone()
            .expect("S2's package"),
    )?;
    let removes_s2 = {
        let group = live_treekem_group(&owner, &group_id).await;
        let snapshot = group.lock().await.to_snapshot_bytes()?;
        let seed = agent_treekem_seed(owner.agent.as_ref(), &hex::decode(&group_id)?);
        let mut copy = x0x::mls::TreeKemMlsGroup::restore(&snapshot, owner_id, &seed)?;
        copy.remove_member_verified(s2_id, &s2_package)?
    };
    let epoch_before = live_epoch(&cast.s1, &group_id).await;
    let genuine = legacy_bound_removal(&cast.fixture).await?;
    let removes_s2_instead = swap_treekem_commit(&genuine, &removes_s2);

    let refused =
        apply_named_group_metadata_event(&cast.s1, removes_s2_instead, owner_id, true, None).await;
    assert!(
        !refused.accepted,
        "a removal of R whose commit keeps R's leaf is refused: {refused:?}"
    );
    assert_eq!(
        live_epoch(&cast.s1, &group_id).await,
        epoch_before,
        "rolled back"
    );
    let installed = apply_named_group_metadata_event(&cast.s1, genuine, owner_id, true, None).await;
    assert!(installed.accepted, "{installed:?}");
    s1_follows_the_owner(&mut cast, b"R is gone").await?;
    cast.shutdown().await;
    Ok(())
}

/// A2 review m-4 (1), by the real routes: a requester approved by the
/// owner seats the roster packages its Welcome holds, so it applies the
/// owner's next removal with no package request.
#[tokio::test]
async fn an_approved_requester_seats_its_welcome_packages_and_follows_the_owner() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let owner = Arc::clone(&fixture.state);
    let owner_id = owner.agent.agent_id();
    let owner_hex = hex_id(&owner_id);
    let group_id = fixture.group_id.clone();
    let (requester, requester_dir) = secure_endpoint_test_state().await?;
    let requester_hex = hex_id(&requester.agent.agent_id());
    let mut request = x0x::groups::JoinRequest::new(
        group_id.clone(),
        requester_hex.clone(),
        None,
        now_millis_u64(),
    );
    request.treekem_key_package_b64 = Some(own_package(&requester, &group_id)?);
    let request_id = request.request_id.clone();
    let stub = {
        let mut groups = owner.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        info.join_requests.insert(request_id.clone(), request);
        hash_only_stub(info)
    };
    requester
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), stub);

    let response = approve_join_request(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), request_id)),
    )
    .await
    .into_response();
    assert_ok(response, "the owner approves").await;
    let mut approved = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::JoinRequestApproved { .. })
    })
    .expect("published approval");
    inline_welcome(&owner, &mut approved).await;
    let applied =
        apply_named_group_metadata_event(&requester, approved, owner_id, true, None).await;
    assert!(applied.accepted, "the requester joins: {applied:?}");
    let seated = roster(&requester, &group_id).await;
    for member in [&owner_hex, &hex_id(&fixture.member_id)] {
        assert!(
            current_member_treekem_key_package(&seated.members_v2[member]).is_some(),
            "the Welcome seats {member}'s package"
        );
    }

    requester.treekem_catchup_throttle.write().await.clear();
    let member_hex = hex_id(&fixture.member_id);
    let response = remove_named_group_member(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let removal = published_removal_event(&owner).expect("removal");
    let applied = apply_named_group_metadata_event(&requester, removal, owner_id, true, None).await;
    assert!(applied.accepted, "{applied:?}");
    assert_eq!(
        live_epoch(&requester, &group_id).await,
        live_epoch(&owner, &group_id).await
    );
    assert!(
        !requester
            .treekem_catchup_throttle
            .read()
            .await
            .keys()
            .any(|key| key.contains(":member:")),
        "no package was missing"
    );
    for state in [&requester, &owner] {
        state.shutdown_notify.send_replace(true);
        state.agent.shutdown().await;
    }
    drop(requester_dir);
    Ok(())
}

/// A2 review m-4 (2), by the real routes: A joins after S1, by the owner's
/// direct add, and is promoted. S1 holds A's package only through the
/// recovery record A's add carried. A's own removal of R applies at S1.
#[tokio::test]
async fn a_later_admins_commit_applies_at_an_earlier_member_from_its_recovery_record() -> Result<()>
{
    let cast = catchup_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let owner_id = owner.agent.agent_id();
    let group_id = cast.fixture.group_id.clone();
    let s1 = Arc::clone(&cast.victim_state);
    let (a, a_dir) = secure_endpoint_test_state().await?;
    let a_id = a.agent.agent_id();
    let a_hex = hex_id(&a_id);
    a.named_groups.write().await.insert(
        group_id.clone(),
        hash_only_stub(&roster(&owner, &group_id).await),
    );

    let package = own_package(&a, &group_id)?;
    let mut added = direct_add_route(&owner, &group_id, &a_hex, "A", &package).await;
    let applied = apply_named_group_metadata_event(&s1, added.clone(), owner_id, true, None).await;
    assert!(applied.accepted, "S1 applies A's add: {applied:?}");
    inline_welcome(&owner, &mut added).await;
    let applied = apply_named_group_metadata_event(&a, added, owner_id, true, None).await;
    assert!(applied.accepted, "A joins: {applied:?}");

    role_route(&owner, &group_id, &a_hex, "admin").await;
    let promotion = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::MemberRoleUpdated { .. })
    })
    .expect("promotion");
    for state in [&s1, &a] {
        let applied =
            apply_named_group_metadata_event(state, promotion.clone(), owner_id, true, None).await;
        assert!(applied.accepted, "{applied:?}");
    }

    // The add commits A's KeyPackage hash. The package itself reaches S1 as
    // the owner's attested recovery record, delivered on its own.
    let recovery = owner
        .treekem_member_key_packages
        .events_matching(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if *member_agent_id == a_hex
            )
        })
        .await
        .into_iter()
        .next()
        .expect("the owner's attested recovery record for A");
    // A recovery courier is cached, not applied to the roster, so it
    // reports no apply.
    let _ = apply_named_group_metadata_event(&s1, recovery, owner_id, true, None).await;
    let s1_roster = roster(&s1, &group_id).await;
    assert!(
        current_member_treekem_key_package(&s1_roster.members_v2[&a_hex]).is_none(),
        "S1's roster holds A's package by hash alone"
    );
    let cached = s1
        .treekem_member_key_packages
        .events_matching(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if *member_agent_id == a_hex
            )
        })
        .await;
    assert!(!cached.is_empty(), "S1 holds A's recovery record");

    let r_hex = hex_id(&cast.fixture.member_id);
    let response = remove_named_group_member(
        State(Arc::clone(&a)),
        owner_extension(),
        Path((group_id.clone(), r_hex)),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "A removes R: {body}");
    let removal = published_removal_event(&a).expect("A's removal");
    s1.treekem_catchup_throttle.write().await.clear();
    let applied = apply_named_group_metadata_event(&s1, removal, a_id, true, None).await;
    assert!(applied.accepted, "S1 applies A's removal: {applied:?}");
    assert_eq!(
        live_epoch(&s1, &group_id).await,
        live_epoch(&a, &group_id).await
    );
    assert!(
        !s1.treekem_catchup_throttle
            .read()
            .await
            .keys()
            .any(|key| key.contains(":member:")),
        "the recovery record was enough"
    );
    a.shutdown_notify.send_replace(true);
    a.agent.shutdown().await;
    drop(a_dir);
    cast.shutdown().await;
    Ok(())
}

/// A2 re-review r-3: the sweep asks only active members, never a removed
/// adder, and asks a bounded number of them for each package.
#[tokio::test]
async fn the_sweep_asks_only_active_members_and_a_bounded_number() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let b_hex = hex_id(&cast.member_b);
    let r_hex = hex_id(&cast.fixture.member_id);
    let mut extra = Vec::new();
    {
        let mut groups = cast.victim_state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        let seat = info.members_v2.get_mut(&b_hex).expect("B");
        seat.treekem_key_package_b64 = None;
        seat.added_by = Some(r_hex.clone());
        info.remove_member(&r_hex, None);
        for _ in 0..5 {
            let id = hex_id(&x0x::identity::AgentKeypair::generate()?.agent_id());
            info.add_member(id.clone(), x0x::groups::GroupRole::Member, None, None);
            extra.push(id);
        }
    }
    spawn_hash_only_treekem_key_package_sweep(&cast.victim_state);
    let prefix = format!("{group_id}:member:{b_hex}:");
    let asked = || -> Vec<String> {
        cast.victim_state
            .treekem_catchup_throttle
            .try_read()
            .map(|throttle| {
                throttle
                    .keys()
                    .filter_map(|key| key.strip_prefix(&prefix).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    wait_until(|| asked().len() >= super::super::committer_leaf::KEY_PACKAGE_SWEEP_CANDIDATES)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let asked = asked();
    assert!(!asked.contains(&r_hex), "a removed adder is never asked");
    assert_eq!(
        asked.len(),
        super::super::committer_leaf::KEY_PACKAGE_SWEEP_CANDIDATES,
        "asked {asked:?}"
    );
    cast.shutdown().await;
    Ok(())
}

/// A2 re-review r-1: a refusal for a missing package pulls the group's
/// commits again once per refused epoch, not on every later refusal, and
/// once more when the package lands.
#[tokio::test]
async fn a_pending_package_pulls_again_once_per_epoch_and_once_when_it_lands() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin = hex_id(&cast.fixture.state.agent.agent_id());
    let admin_package = roster(&cast.victim_state, &group_id).await.members_v2[&admin]
        .treekem_key_package_b64
        .clone()
        .expect("setup: the admin's package");
    victim_holds_the_admin_by_hash(&cast).await;
    cast.victim_state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let state = &cast.victim_state;
    let pulling = || {
        state
            .treekem_epoch_ahead_targets
            .try_lock()
            .is_ok_and(|targets| targets.contains_key(&group_id))
    };
    let epoch = cast.epoch_before + 1;

    // A refusal already pulled for this epoch, and that pull has ended.
    assert!(state
        .treekem_package_repulls
        .lock()
        .expect("repulls")
        .note_refusal(&group_id, epoch));
    super::super::committer_leaf::pull_again_after_package(state, &group_id, epoch).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !pulling(),
        "a later refusal at the same epoch does not pull again"
    );

    assert!(
        apply_targeted_member_key_package(state, &group_id, &admin, &admin_package).await,
        "the package lands"
    );
    wait_until(pulling).await;
    assert!(
        pulling(),
        "the landed package pulls the refused epoch again"
    );
    cast.shutdown().await;
    Ok(())
}

/// A2 re-review r-6: the sweep is spawned, so the caller (the startup join
/// task, before its rendezvous advertisement) never waits on the roster.
#[tokio::test]
async fn the_key_package_sweep_never_holds_up_its_caller() -> Result<()> {
    let cast = catchup_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let admin = hex_id(&cast.fixture.state.agent.agent_id());
    victim_holds_the_admin_by_hash(&cast).await;
    let roster_guard = cast.victim_state.named_groups.write().await;
    spawn_hash_only_treekem_key_package_sweep(&cast.victim_state);
    drop(roster_guard);
    let prefix = format!("{group_id}:member:{admin}:");
    let asked = || {
        cast.victim_state
            .treekem_catchup_throttle
            .try_read()
            .is_ok_and(|throttle| throttle.keys().any(|k| k.starts_with(&prefix)))
    };
    wait_until(asked).await;
    assert!(asked(), "the spawned sweep runs once the roster is free");
    cast.shutdown().await;
    Ok(())
}

/// A1 review m-4: a `treekem:` binding that is none of the written forms is
/// refused, rather than admitted as one that names no bytes. Another
/// plane's binding names no TreeKEM bytes, so only its author delivers it.
#[test]
fn a_malformed_treekem_add_binding_is_refused() {
    let with_binding = |binding: &str| {
        let mut commit = fake_group_state_commit("g", 1, "a");
        commit.security_binding = Some(binding.to_string());
        commit
    };
    let commit_b64 = BASE64.encode(b"tree commit");
    for malformed in [
        "treekem:epoch=5:Commit=ab",
        "treekem:epoch=5;junk=1",
        "treekem:epoch=05",
    ] {
        assert!(
            !treekem_add_binding_admits(
                &with_binding(malformed),
                5,
                &commit_b64,
                None,
                None,
                None,
                None,
                None
            ),
            "{malformed}"
        );
    }
    assert!(treekem_add_binding_admits(
        &with_binding("gss:epoch=5"),
        5,
        &commit_b64,
        None,
        None,
        None,
        None,
        None
    ));
}
