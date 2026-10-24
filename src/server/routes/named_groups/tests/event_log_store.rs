//! Survivor re-key A4: the catch-up log on disk. A member serves every
//! commit-bearing event it applied, after a restart too, so a member who
//! missed some of them converges from any other member.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::epoch_ahead_catchup::{
    catchup_request_from, published_removal_event, survivor_relay_fixture, SurvivorRelay,
};
use super::signer_delivery::{
    admission_route, ban_route, direct_add_route, hex_id, newcomer, owner_extension, published,
    rename_route, role_route, roster, s1_follows_the_owner, s2_applies, unban_route,
};
use super::*;

/// `server` answers a catch-up request from `requester` on the real serve
/// path, and returns the page it sent.
async fn served_page(
    server: &Arc<AppState>,
    requester: &Arc<AppState>,
    group_id: &str,
) -> Option<TreeKemCatchupResponse> {
    let requester_id = requester.agent.agent_id();
    let request = {
        let groups = requester.named_groups.read().await;
        let info = groups.get(group_id).expect("group on the requester");
        catchup_request_from(info, group_id, &requester_id)
    };
    let before = server
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len();
    handle_treekem_catchup_request(server, &requester_id, true, request).await;
    let recorded = server
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder");
    recorded
        .get(before..)
        .and_then(|sent| sent.last())
        .map(|bytes| serde_json::from_slice(bytes).expect("a catch-up page"))
}

/// `requester` catches up from `server` alone on the real paths: it applies
/// each page and asks for the next one while the page says it was cut
/// short. Returns how many pages it applied.
async fn catch_up(server: &Arc<AppState>, requester: &Arc<AppState>, group_id: &str) -> usize {
    let server_id = server.agent.agent_id();
    let mut pages = 0;
    while let Some(page) = served_page(server, requester, group_id).await {
        if page.events.is_empty() {
            break;
        }
        pages += 1;
        let more = page.truncated;
        handle_treekem_catchup_response(requester, &server_id, true, page).await;
        if !more || pages > 16 {
            break;
        }
    }
    pages
}

/// The owner renames the room, then removes R. S2 applies both from the
/// owner and returns `(rename, removal)`.
async fn rename_then_remove(
    cast: &SurvivorRelay,
) -> (NamedGroupMetadataEvent, NamedGroupMetadataEvent) {
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let r_hex = hex_id(&cast.fixture.member_id);
    rename_route(&owner, &group_id, "Family").await;
    let rename = published(&owner, |event| {
        matches!(event, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("the rename is published");
    let removed = remove_named_group_member(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), r_hex)),
    )
    .await
    .into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the owner removes R");
    let removal = published_removal_event(&owner).expect("the removal is published");
    s2_applies(cast, &rename).await;
    s2_applies(cast, &removal).await;
    (rename, removal)
}

/// S1 was away for a rename and a removal. It asks S2 alone, and the page S2
/// serves brings it to the owner's name, roster and epoch.
#[tokio::test]
async fn survivor_who_missed_a_rename_and_a_removal_converges() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    rename_then_remove(&cast).await;

    let pages = catch_up(&cast.s2, &cast.s1, &group_id).await;
    assert_eq!(pages, 2, "one event a page");

    assert_eq!(roster(&cast.s1, &group_id).await.name, "Family");
    s1_follows_the_owner(&mut cast, b"after the rename and the removal").await?;
    cast.shutdown().await;
    Ok(())
}

/// S2 as it comes back after a restart: a new daemon state on S2's data
/// directory and identity.
async fn restarted_s2(cast: &SurvivorRelay) -> Result<Arc<AppState>> {
    secure_endpoint_test_state_at(cast.s2_dir(), Arc::clone(&cast.s2.agent)).await
}

fn room_dir(state: &AppState, group_id: &str) -> std::path::PathBuf {
    state
        .treekem_dir
        .join("event-log")
        .join(crate::server::routes::named_groups::event_log_store::room_dir_name(group_id))
}

async fn logged_kinds(
    state: &AppState,
    group_id: &str,
) -> std::collections::BTreeSet<&'static str> {
    let logs = state.treekem_event_log.read().await;
    logs.get(group_id)
        .map(|events| events.iter().map(named_group_metadata_event_kind).collect())
        .unwrap_or_default()
}

/// S2 applied a rename and a removal, then restarted. S1 was away for
/// both, asks the restarted S2 alone, and converges.
#[tokio::test]
async fn event_log_survives_restart_and_serves_catchup() -> Result<()> {
    let mut cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    rename_then_remove(&cast).await;

    let restarted = restarted_s2(&cast).await?;
    assert_eq!(
        logged_kinds(&restarted, &group_id).await,
        ["group_metadata_updated", "member_removed"]
            .into_iter()
            .collect(),
        "the restarted S2 reloads both events from disk"
    );
    let pages = catch_up(&restarted, &cast.s1, &group_id).await;
    assert_eq!(pages, 2, "the restarted S2 serves both events");

    assert_eq!(roster(&cast.s1, &group_id).await.name, "Family");
    s1_follows_the_owner(&mut cast, b"after the restart").await?;
    restarted.shutdown_notify.send_replace(true);
    cast.shutdown().await;
    Ok(())
}

/// Every kind the owner's routes seal is logged where it is authored and
/// where it is applied, and is still there after a restart.
#[tokio::test]
async fn event_log_holds_every_commit_bearing_kind() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let r_hex = hex_id(&cast.fixture.member_id);
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    let (nan, nan_package) = newcomer(0x71)?;
    let nan_hex = hex_id(&nan);

    let mut events = Vec::new();
    ban_route(&owner, &group_id, &r_hex).await;
    events.push(
        published(&owner, |e| {
            matches!(e, NamedGroupMetadataEvent::MemberBanned { .. })
        })
        .expect("ban"),
    );
    unban_route(&owner, &group_id, &r_hex).await;
    events.push(
        published(&owner, |e| {
            matches!(e, NamedGroupMetadataEvent::MemberUnbanned { .. })
        })
        .expect("unban"),
    );
    rename_route(&owner, &group_id, "Family").await;
    events.push(
        published(&owner, |e| {
            matches!(e, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
        })
        .expect("rename"),
    );
    admission_route(&owner, &group_id).await;
    events.push(
        published(&owner, |e| {
            matches!(e, NamedGroupMetadataEvent::PolicyUpdated { .. })
        })
        .expect("policy"),
    );
    role_route(&owner, &group_id, &s2_hex, "admin").await;
    events.push(
        published(&owner, |e| {
            matches!(e, NamedGroupMetadataEvent::MemberRoleUpdated { .. })
        })
        .expect("role"),
    );
    events.push(direct_add_route(&owner, &group_id, &nan_hex, "Nan", &nan_package).await);
    let removed = remove_named_group_member(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), nan_hex.clone())),
    )
    .await
    .into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the owner removes Nan");
    events.push(published_removal_event(&owner).expect("removal"));
    for event in &events {
        s2_applies(&cast, event).await;
    }

    let expected: std::collections::BTreeSet<&'static str> = [
        "member_banned",
        "member_unbanned",
        "group_metadata_updated",
        "policy_updated",
        "member_role_updated",
        "member_added",
        "member_removed",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        logged_kinds(&owner, &group_id).await,
        expected,
        "the author logs"
    );
    assert_eq!(
        logged_kinds(&cast.s2, &group_id).await,
        expected,
        "S2 logs what it applied"
    );
    let restarted = restarted_s2(&cast).await?;
    assert_eq!(
        logged_kinds(&restarted, &group_id).await,
        expected,
        "and all of it is on disk"
    );

    // The join-request lifecycle carries a commit too. An admin's
    // rejection is logged. A request and its cancellation come from a
    // requester who never serves catch-up, and apply only from it, so no
    // member logs them (A4 review I-2).
    let requester = hex_id(&newcomer(0x72)?.0);
    let signed = named_group_metadata_event_commit(&events[0]).cloned();
    let created = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_id.clone(),
        request_id: "request".to_string(),
        requester_agent_id: requester.clone(),
        message: None,
        ts: 1,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: signed.clone(),
    };
    let rejected = NamedGroupMetadataEvent::JoinRequestRejected {
        group_id: group_id.clone(),
        request_id: "request".to_string(),
        actor: hex_id(&owner.agent.agent_id()),
        requester_agent_id: requester,
        commit: signed,
    };
    remember_commit_bearing_event(&cast.s2, &created).await;
    remember_commit_bearing_event(&cast.s2, &rejected).await;
    let kinds = logged_kinds(&cast.s2, &group_id).await;
    assert!(kinds.contains("join_request_rejected"));
    assert!(!kinds.contains("join_request_created"));
    restarted.shutdown_notify.send_replace(true);
    cast.shutdown().await;
    Ok(())
}

/// S2 is removed. Its departure takes the log off disk as well as out of
/// memory, so a restart cannot bring it back (#363, #376).
#[tokio::test]
async fn event_log_wipe_on_departure_removes_disk_copy() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let owner = Arc::clone(&cast.fixture.state);
    let group_id = cast.fixture.group_id.clone();
    let s2_hex = hex_id(&cast.s2.agent.agent_id());
    rename_route(&owner, &group_id, "Family").await;
    let rename = published(&owner, |e| {
        matches!(e, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("rename");
    s2_applies(&cast, &rename).await;
    let dir = room_dir(&cast.s2, &group_id);
    assert!(dir.exists(), "S2 logged the rename on disk");

    let removed = remove_named_group_member(
        State(Arc::clone(&owner)),
        owner_extension(),
        Path((group_id.clone(), s2_hex)),
    )
    .await
    .into_response();
    assert_eq!(removed.status(), StatusCode::OK, "the owner removes S2");
    let removal = published_removal_event(&owner).expect("removal");
    s2_applies(&cast, &removal).await;

    assert!(!dir.exists(), "the departure removes the disk copy");
    assert!(cast
        .s2
        .treekem_event_log
        .read()
        .await
        .get(&group_id)
        .is_none());
    let restarted = restarted_s2(&cast).await?;
    assert!(restarted.treekem_event_log.read().await.is_empty());
    restarted.shutdown_notify.send_replace(true);
    cast.shutdown().await;
    Ok(())
}

/// A wipe completes while an append is waiting for the log lock. The
/// append then finds the room gone and writes nothing.
#[tokio::test]
async fn an_append_racing_a_wipe_does_not_recreate_the_directory() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let s2 = Arc::clone(&cast.s2);
    let owner = Arc::clone(&cast.fixture.state);
    rename_route(&owner, &group_id, "Family").await;
    let rename = published(&owner, |e| {
        matches!(e, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("rename");
    s2_applies(&cast, &rename).await;
    admission_route(&owner, &group_id).await;
    let policy = published(&owner, |e| {
        matches!(e, NamedGroupMetadataEvent::PolicyUpdated { .. })
    })
    .expect("policy");
    let dir = room_dir(&s2, &group_id);
    assert!(dir.exists());

    let mut log = s2.treekem_event_log.write().await;
    let append = tokio::spawn({
        let s2 = Arc::clone(&s2);
        async move { remember_commit_bearing_event(&s2, &policy).await }
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!append.is_finished(), "the append waits for the log lock");
    // The departure: the room leaves the roster, then its log is wiped.
    s2.named_groups.write().await.remove(&group_id);
    log.wipe_room(&group_id).await;
    drop(log);
    append.await?;

    assert!(!dir.exists(), "the append did not bring the directory back");
    assert!(s2.treekem_event_log.read().await.get(&group_id).is_none());
    cast.shutdown().await;
    Ok(())
}

/// S2's log dropped events S1 still needs. S2 serves S1 no page, and says
/// so. A requester past the dropped revision is still served.
#[tokio::test]
async fn a_gap_past_the_cap_is_not_served_and_says_so() -> Result<()> {
    let cast = survivor_relay_fixture().await?;
    let group_id = cast.fixture.group_id.clone();
    let owner = Arc::clone(&cast.fixture.state);
    let base = roster(&cast.s1, &group_id).await.state_revision;
    rename_route(&owner, &group_id, "Family").await;
    let rename = published(&owner, |e| {
        matches!(e, NamedGroupMetadataEvent::GroupMetadataUpdated { .. })
    })
    .expect("rename");
    for step in 1..=(crate::server::routes::named_groups::event_log_store::ROOM_CAP as u64 + 1) {
        let NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id,
            actor,
            commit: Some(commit),
            ..
        } = rename.clone()
        else {
            panic!("a signed rename");
        };
        let mut commit = commit;
        commit.revision = base + step;
        commit.state_hash = format!("filler-{step}");
        let filler = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id,
            revision: base + step,
            actor,
            name: Some(format!("name {step}")),
            description: None,
            commit: Some(commit),
        };
        remember_commit_bearing_event(&cast.s2, &filler).await;
    }
    assert_eq!(
        cast.s2
            .treekem_event_log
            .read()
            .await
            .evicted_through(std::slice::from_ref(&group_id)),
        Some(base + 1)
    );

    let page = served_page(&cast.s2, &cast.s1, &group_id)
        .await
        .expect("S2 answers");
    assert!(page.events.is_empty(), "no page with a hole in it");
    assert_eq!(page.log_evicted_through, Some(base + 1), "and it says so");

    // A requester at the dropped revision needs nothing that was dropped.
    let s1_id = cast.s1.agent.agent_id();
    let mut request = {
        let groups = cast.s1.named_groups.read().await;
        catchup_request_from(groups.get(&group_id).expect("group"), &group_id, &s1_id)
    };
    request.from_revision = base + 1;
    handle_treekem_catchup_request(&cast.s2, &s1_id, true, request).await;
    let served: TreeKemCatchupResponse = serde_json::from_slice(
        cast.s2
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("recorder")
            .last()
            .expect("a page"),
    )?;
    assert!(served.log_evicted_through.is_none());
    assert_eq!(served.events.len().min(1), 1, "it is served");
    assert_eq!(
        commit_bearing_event_sort_key(&served.events[0]).0,
        base + 2,
        "from the first revision it still holds"
    );
    cast.shutdown().await;
    Ok(())
}
