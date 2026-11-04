use super::*;

// How big a Noetic-shaped room's join result is: an owner and 1 to 3
// members, a private_secure (TreeKEM) room, every member joining by its
// own invite through the real routes. Over `MAX_PAYLOAD_BYTES` a join
// result takes the control-blob reference and chunk pull instead of one
// inline frame.

async fn member_state(
    dir: &std::path::Path,
    name: &str,
    with_user: bool,
) -> anyhow::Result<Arc<AppState>> {
    let jdir = dir.join(name);
    tokio::fs::create_dir_all(&jdir).await?;
    let mut builder = Agent::builder()
        .with_machine_key(jdir.join("machine.key"))
        .with_agent_key(x0x::identity::AgentKeypair::generate()?)
        .with_agent_cert_path(jdir.join("agent.cert"))
        .with_peer_cache_disabled()
        .with_contact_store_path(jdir.join("contacts.json"));
    if with_user {
        builder = builder.with_user_key(x0x::identity::UserKeypair::generate()?);
    }
    let agent = Arc::new(builder.build().await?);
    secure_endpoint_test_state_at(&jdir, agent).await
}

fn hex_id(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

async fn invite_link(
    state: &Arc<AppState>,
    group: &str,
    joiner: &AppState,
) -> anyhow::Result<String> {
    let (_invite, link) = mint_invite_transaction(
        state,
        group,
        3_600,
        Some(joiner.agent.agent_id()),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint invite: {e:?}"))?;
    Ok(link)
}

async fn join_by(joiner: &Arc<AppState>, link: String) -> anyhow::Result<()> {
    let response = join_group_via_invite(
        State(Arc::clone(joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: Some("a member with a long display name".to_string()),
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    anyhow::ensure!(status == StatusCode::OK, "join: {status} {:?}", bytes);
    Ok(())
}

fn attempt_of(joiner: &AppState, stable: &str) -> Option<(String, NamedGroupMetadataEvent)> {
    let attempts = joiner.pending_join_attempts.lock().ok()?;
    let entry = attempts.get(&join_result_key(stable, &hex_id(joiner)))?;
    Some((
        entry.attempt_id.clone(),
        entry.stored_resend.as_ref()?.event.clone(),
    ))
}

/// The exact bytes the owner's FetchRequest arm decides to serve.
async fn served_bytes(
    owner: &Arc<AppState>,
    joiner: &AppState,
    stable: &str,
    attempt: &str,
    from: Option<u64>,
) -> Option<Vec<u8>> {
    let member = hex_id(joiner);
    owner
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .ok()?
        .clear();
    super::super::handle_join_result_message(
        owner,
        &joiner.agent.agent_id(),
        true,
        JoinResultMessage::FetchRequest {
            signed_by: None,
            group_id: stable.to_string(),
            member_agent_id: member.clone(),
            from_revision: from,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: true,
            attempt_id: Some(attempt.to_string()),
        },
    )
    .await;
    let serves = owner
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .ok()?;
    serves
        .iter()
        .rev()
        .find(|(to, group, _)| *to == member && group == stable)
        .map(|(_, _, payload)| payload.clone())
}

/// A room of `members` joiners; invites minted up front (so later joiners
/// carry the earlier adds as intervening events) or one by one. Returns
/// the served join-result size of each joiner, in join order.
async fn room_sizes(members: usize, up_front: bool, with_user: bool) -> anyhow::Result<Vec<usize>> {
    let dir = tempfile::tempdir()?;
    let owner = member_state(dir.path(), "owner", with_user).await?;
    let created = create_named_group(
        State(Arc::clone(&owner)),
        Json(CreateGroupRequest {
            name: "Our family room".to_string(),
            description: "Noetic room".to_string(),
            display_name: Some("Owner".to_string()),
            preset: Some("private_secure".to_string()),
            policy: None,
        }),
    )
    .await
    .into_response();
    let status = created.status();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(created.into_body(), usize::MAX).await?)?;
    anyhow::ensure!(status == StatusCode::CREATED, "{body}");
    let group = body["group_id"].as_str().expect("group id").to_string();
    let (stable, base) = {
        let groups = owner.named_groups.read().await;
        let info = groups.get(&group).expect("room");
        (info.stable_group_id().to_string(), info.state_revision)
    };
    let mut joiners = Vec::new();
    for i in 0..members {
        joiners.push(member_state(dir.path(), &format!("m{i}"), with_user).await?);
    }
    let mut links = Vec::new();
    if up_front {
        for joiner in &joiners {
            links.push(invite_link(&owner, &group, joiner).await?);
        }
    }
    let mut sizes = Vec::new();
    for (i, joiner) in joiners.iter().enumerate() {
        let link = if up_front {
            links[i].clone()
        } else {
            invite_link(&owner, &group, joiner).await?
        };
        join_by(joiner, link).await?;
        let (attempt, joined) = attempt_of(joiner, &stable).expect("attempt");
        anyhow::ensure!(
            apply_named_group_metadata_event(&owner, joined, joiner.agent.agent_id(), true, None)
                .await
                .accepted,
            "the owner seals the add"
        );
        let from = if up_front { Some(base) } else { None };
        let bytes = served_bytes(&owner, joiner, &stable, &attempt, from)
            .await
            .expect("a served result");
        sizes.push(bytes.len());
    }
    Ok(sizes)
}

/// WHY (round 5): a Noetic join result can exceed `MAX_PAYLOAD_BYTES` and
/// take the control-blob reference and chunk pull, so that pull must
/// survive a slow gossip inbox too. Measured (bytes, limit 49152): one by
/// one, members 1 to 4 get 44166, 47286, 48818 and 51938; with
/// invites minted up front, the 2nd and 3rd get 96369 and 150267
/// (they carry the earlier adds). Agent user certificates do not change
/// the size.
#[tokio::test]
async fn a_noetic_join_result_can_exceed_the_inline_limit() -> anyhow::Result<()> {
    let limit = x0x::dm::MAX_PAYLOAD_BYTES;
    for with_user in [false, true] {
        let one_by_one = room_sizes(4, false, with_user).await?;
        let up_front = room_sizes(3, true, with_user).await?;
        println!(
            "JOIN-RESULT-SIZE user_certs={with_user} one_by_one={one_by_one:?} up_front={up_front:?} limit={limit}"
        );
        assert!(
            one_by_one[..3].iter().all(|size| *size <= limit),
            "{one_by_one:?}"
        );
        assert!(
            one_by_one[3] > limit,
            "a 4th member's result is oversized: {one_by_one:?}"
        );
        assert!(up_front[1] > limit && up_front[2] > limit, "{up_front:?}");
    }
    Ok(())
}
