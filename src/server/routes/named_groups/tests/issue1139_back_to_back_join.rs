use super::*;

// #1139 — back-to-back Home joins. The authority seals J1's add (r+1) and
// then J2's add (r+2) from the same invite base r. J2's stub holds r; the
// only thing J2 ever receives is its OWN join result (the r+2 MemberAdded,
// its inline Welcome, the served intervening chain [r+1] and the owner's
// v2 head attestation). The r+1 gossip copy was published before J2 was
// listening (rc5 home-b1: nuremberg joined 1.8 s after sfo's add sealed).

const OWNER_SEED: [u8; 32] = [0x39; 32];

struct SealedAdd {
    event: NamedGroupMetadataEvent,
    commit: x0x::groups::GroupStateCommit,
    member_hex: String,
}

/// Seal one real Home add on the authority exactly like the bound-joiner
/// fixture: owner mandate, owner-certified state commit, TreeKEM add with
/// an INLINE Welcome (socket-free), advancing `next` in place.
#[allow(clippy::too_many_arguments)]
async fn seal_home_add(
    state: &Arc<AppState>,
    next: &mut x0x::groups::GroupInfo,
    group_key: &str,
    stable_group_id: &str,
    owner: &x0x::identity::UserKeypair,
    member_kp: &x0x::identity::AgentKeypair,
    prepared: crate::mls::treekem::PreparedMember,
) -> Result<SealedAdd> {
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member = member_kp.agent_id();
    let member_hex = hex::encode(member.as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(owner, member_kp)?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    let now_ms = now_millis_u64();
    let group = state
        .treekem_groups
        .read()
        .await
        .get(group_key)
        .cloned()
        .expect("Home TreeKEM group");
    let mut group = group.lock().await;
    let epoch = group.epoch() + 1;
    next.roster_revision += 1;
    let revision = next.roster_revision;
    next.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    next.set_member_treekem_key_package(&member_hex, kp_b64.clone());
    next.set_member_certificate(&member_hex, cert.clone())
        .expect("owner certificate binds to seat");
    next.secret_epoch = epoch;
    let direct_recovery = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.to_string(),
        stable_group_id: Some(stable_group_id.to_string()),
        member_agent_id: member_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: authority_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(kp_b64),
        kem_public_key_b64: None,
        kem_signature_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),
        certificate_b64: None,
    };
    next.security_binding = treekem_recovery_security_binding(epoch, &direct_recovery);
    let mandate = mint_owner_mandate_for_seat(
        state,
        next,
        epoch,
        &member_hex,
        &authority_hex,
        "",
        Some(&cert),
        now_ms,
    )
    .await
    .expect("owner signs mandate");
    let commit =
        seal_commit_owner_certified(state, next, state.agent.identity().agent_keypair(), now_ms)
            .await?;
    let out = group.add_member(member, prepared.key_package_bytes())?;
    drop(group);
    let event = NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: Vec::new(),
        group_id: stable_group_id.to_string(),
        revision,
        actor: authority_hex,
        agent_id: member_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some(BASE64.encode(out.commit)),
        treekem_welcome_b64: Some(BASE64.encode(out.welcome)),
        welcome_ref: None,
        treekem_epoch: Some(epoch),
        treekem_key_package_hash: next
            .members_v2
            .get(&member_hex)
            .and_then(|m| m.treekem_key_package_hash.clone()),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(&cert)?)),
        owner_mandate: Some(mandate),
        commit: Some(commit.clone()),
    };
    Ok(SealedAdd {
        event,
        commit,
        member_hex,
    })
}

struct BackToBack {
    _authority: Arc<AppState>,
    authority_id: AgentId,
    j1: Arc<AppState>,
    j2: Arc<AppState>,
    group_key: String,
    stable_group_id: String,
    add_j1: SealedAdd,
    add_j2: SealedAdd,
    /// What the authority serves J2 for a fetch from the stub revision.
    j2_result: JoinResultMessage,
    /// The same result as served by a pre-#1139 authority.
    j2_legacy_result: JoinResultMessage,
    j1_attempt: String,
    j2_attempt: String,
}

async fn joiner_state(
    dir: &std::path::Path,
    name: &str,
    kp: x0x::identity::AgentKeypair,
) -> Result<Arc<AppState>> {
    let jdir = dir.join(name);
    tokio::fs::create_dir_all(&jdir).await?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.join("machine.key"))
            .with_agent_key(kp)
            .with_agent_cert_path(jdir.join("agent.cert"))
            // Home joiners are the owner's own devices: the owner key
            // issues each one an agent certificate chaining to the owner.
            .with_user_key(x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.join("contacts.json"))
            .build()
            .await?,
    );
    secure_endpoint_test_state_at(&jdir, agent).await
}

/// Run the REAL join route on `joiner` and return its live attempt id.
async fn route_join(
    joiner: &Arc<AppState>,
    link: &str,
    stable_group_id: &str,
    owner_pin: &str,
) -> Result<String> {
    let response = join_group_via_invite(
        State(Arc::clone(joiner)),
        Json(JoinGroupRequest {
            invite: link.to_string(),
            display_name: None,
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(owner_pin.to_string()),
        }),
    )
    .await
    .into_response();
    let status = response.status();
    if !status.is_success() {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        anyhow::bail!(
            "join route returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let key = join_result_key(
        stable_group_id,
        &hex::encode(joiner.agent.agent_id().as_bytes()),
    );
    joiner
        .pending_join_attempts
        .lock()
        .expect("attempt registry")
        .get(&key)
        .map(|a| a.attempt_id.clone())
        .ok_or_else(|| anyhow::anyhow!("route registered no attempt"))
}

/// J2's stub is the production shape: ONE real owner-countersigned invite
/// (`mint_invite_transaction`, base r) consumed by the REAL
/// `join_group_via_invite` route on both joiners (invite-seeded roster
/// clock, #468 A5 lineage, live bound attempt, own KeyPackage).
async fn build_back_to_back(dir: &std::path::Path) -> Result<BackToBack> {
    let authority = super::super::super::home::tests::owned_state(dir, OWNER_SEED).await?;
    super::super::super::home::provision_home(&authority).await;
    let owner = authority
        .agent
        .identity()
        .user_keypair()
        .expect("owned Home");
    let (_, provisioned) = super::super::super::home::find_home(&authority, &owner.user_id())
        .await
        .expect("provisioned Home");
    let group_key = provisioned.mls_group_id.clone();
    let (_invite, link) = mint_invite_transaction(
        &authority,
        &group_key,
        3_600,
        None,
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint invite: {e:?}"))?;
    let base = authority
        .named_groups
        .read()
        .await
        .get(&group_key)
        .cloned()
        .expect("authority Home");
    let stable_group_id = base.stable_group_id().to_string();
    let group_id_bytes = hex::decode(&group_key)?;

    let j1_kp = x0x::identity::AgentKeypair::generate()?;
    let j1_bytes = j1_kp.to_bytes();
    let j2_kp = x0x::identity::AgentKeypair::generate()?;
    let j2_bytes = j2_kp.to_bytes();
    let j1 = joiner_state(dir, "j1", j1_kp).await?;
    let j2 = joiner_state(dir, "j2", j2_kp).await?;
    // Each joiner's KeyPackage uses its production-derived TreeKEM seed so
    // the Welcome it receives is consumable.
    let j1_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(
        j1.agent.agent_id(),
        &agent_treekem_seed(&j1.agent, &group_id_bytes),
    )?;
    let j2_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(
        j2.agent.agent_id(),
        &agent_treekem_seed(&j2.agent, &group_id_bytes),
    )?;

    // Back-to-back seals from the same base: r+1 (J1) then r+2 (J2).
    let mut next = base.clone();
    let add_j1 = seal_home_add(
        &authority,
        &mut next,
        &group_key,
        &stable_group_id,
        owner,
        &x0x::identity::AgentKeypair::from_bytes(&j1_bytes.0, &j1_bytes.1)?,
        j1_prepared,
    )
    .await?;
    let add_j2 = seal_home_add(
        &authority,
        &mut next,
        &group_key,
        &stable_group_id,
        owner,
        &x0x::identity::AgentKeypair::from_bytes(&j2_bytes.0, &j2_bytes.1)?,
        j2_prepared,
    )
    .await?;
    assert_eq!(add_j1.commit.revision, base.state_revision + 1);
    assert_eq!(add_j2.commit.revision, base.state_revision + 2);
    assert_eq!(
        add_j2.commit.prev_state_hash.as_deref(),
        Some(add_j1.commit.state_hash.as_str()),
        "r+2 chains from r+1, not from the invite base J2 holds"
    );
    // Publish the sealed head on the authority (what the live seal path
    // leaves behind) so the fetch-serving path sees the retained log.
    authority
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), next.clone());
    // The live seal path (`add_treekem_named_group_member`) logs every
    // sealed MemberAdded in the in-memory TreeKEM event log.
    remember_treekem_membership_event(&authority, &add_j1.event).await;
    remember_treekem_membership_event(&authority, &add_j2.event).await;

    // Exactly what the authority serves J2's FetchRequest from the stub
    // revision: stage_join_result's v2 owner attestation plus
    // intervening_chain_from (named_groups.rs, FetchRequest arm).
    let chain = intervening_chain_from(&next, base.state_revision, add_j2.commit.revision);
    assert_eq!(chain.len(), 1, "the authority serves the r+1 link");
    let head_attestation = HeadAttestation::sign_for_terminal(
        &stable_group_id,
        &add_j2.commit,
        &add_j2.member_hex,
        match &add_j2.event {
            NamedGroupMetadataEvent::MemberAdded { treekem_epoch, .. } => *treekem_epoch,
            _ => None,
        },
        owner,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    // A pre-#1139 (legacy) authority serves no intervening events.
    let j2_legacy_result = JoinResultMessage::Result {
        event: Box::new(add_j2.event.clone()),
        chain,
        head_attestation: Some(Box::new(head_attestation)),
        roster_certificates_b64: Vec::new(),
        intervening_events: Vec::new(),
    };
    // #1139: what the fixed FetchRequest arm adds from the authority's log.
    let intervening = super::super::intervening_membership_events(
        &authority,
        std::slice::from_ref(&stable_group_id),
        base.state_revision,
        add_j2.commit.revision,
    )
    .await;
    let j2_result = match j2_legacy_result.clone() {
        JoinResultMessage::Result {
            event,
            chain,
            head_attestation,
            roster_certificates_b64,
            ..
        } => JoinResultMessage::Result {
            event,
            chain,
            head_attestation,
            roster_certificates_b64,
            intervening_events: intervening,
        },
        other => other,
    };

    let owner_pin = hex::encode(owner.user_id().as_bytes());
    let j1_attempt = route_join(&j1, &link, &stable_group_id, &owner_pin).await?;
    let j2_attempt = route_join(&j2, &link, &stable_group_id, &owner_pin).await?;
    Ok(BackToBack {
        j1_attempt,
        j2_attempt,
        authority_id: authority.agent.agent_id(),
        _authority: authority,
        j1,
        j2,
        group_key,
        stable_group_id,
        add_j1,
        add_j2,
        j2_result,
        j2_legacy_result,
    })
}

async fn join_state(joiner: &Arc<AppState>, group_key: &str) -> &'static str {
    let info = joiner
        .named_groups
        .read()
        .await
        .get(group_key)
        .cloned()
        .expect("stub");
    let local = hex::encode(joiner.agent.agent_id().as_bytes());
    local_join_membership_state(joiner, &info, &local).await
}

async fn deliver_j2(s: &BackToBack, result: &JoinResultMessage) {
    super::super::handle_join_result_message_bound(
        &s.j2,
        &s.authority_id,
        true,
        result.clone(),
        Some(s.j2_attempt.as_str()),
    )
    .await;
}

async fn deliver_j2_legacy_result(s: &BackToBack) {
    deliver_j2(s, &s.j2_legacy_result).await;
}

async fn deliver_j2_result(s: &BackToBack) {
    deliver_j2(s, &s.j2_result).await;
}

/// The page the authority's TreeKEM catch-up responder serves for J2's
/// request (`handle_treekem_catchup_request`: every logged membership
/// event past J2's revision OR epoch).
fn catchup_page(s: &BackToBack) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: s.stable_group_id.clone(),
        events: vec![s.add_j1.event.clone(), s.add_j2.event.clone()],
        truncated: false,
    }
}

/// WHY (#1139): pins the mechanism. J2 holds only its OWN join result
/// (r+2 + Welcome + served chain [r+1] + owner v2 attestation). The r+2
/// apply fails prev-hash against the r stub; TreeKEM never adopts across
/// a gap (`try_adopt_member_added_across_gap`); the #818 classifier
/// records the owner-anchored stale-base gap, queues r+2 and asks the
/// authority for TreeKEM catch-up. Re-delivering the same result (the
/// live joiner re-fetched ~44 times) changes nothing: convergence depends
/// ENTIRELY on a separate catch-up round trip, even though the served
/// chain already carries r+1. Positive control: J1 (gapless) converges.
#[tokio::test]
async fn issue1139_legacy_join_result_alone_leaves_second_joiner_pending() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;

    super::super::handle_join_result_message_bound(
        &s.j1,
        &s.authority_id,
        true,
        JoinResultMessage::Result {
            event: Box::new(s.add_j1.event.clone()),
            chain: Vec::new(),
            head_attestation: None,
            roster_certificates_b64: Vec::new(),
            intervening_events: Vec::new(),
        },
        Some(s.j1_attempt.as_str()),
    )
    .await;
    assert_eq!(join_state(&s.j1, &s.group_key).await, "active");
    assert!(s.j1.treekem_groups.read().await.contains_key(&s.group_key));

    for _ in 0..3 {
        deliver_j2_legacy_result(&s).await;
    }
    assert_eq!(
        join_state(&s.j2, &s.group_key).await,
        "pending_authority_commit"
    );
    assert!(
        !s.j2.treekem_groups.read().await.contains_key(&s.group_key),
        "no Welcome consumed: the await_treekem poll never confirms"
    );
    let info =
        s.j2.named_groups
            .read()
            .await
            .get(&s.group_key)
            .cloned()
            .expect("stub");
    assert!(!info.members_v2.contains_key(&s.add_j2.member_hex));
    assert!(!info.is_fork_quarantined(), "a gap, not a fork");
    assert_eq!(
        info.invite_lineage
            .as_ref()
            .and_then(|l| l.anchored_gap_refusal.as_ref())
            .map(|r| r.reason.as_str()),
        Some("owner_attested_stale_base_gap"),
        "#818 classifier ran"
    );
    let queued =
        s.j2.treekem_pending_events
            .read()
            .await
            .get(&s.group_key)
            .map_or(0, |q| q.len());
    assert_eq!(queued, 1, "r+2 queued once for replay (deduplicated)");
    let authority_hex = hex::encode(s.authority_id.as_bytes());
    assert!(
        s.j2.treekem_catchup_throttle
            .read()
            .await
            .keys()
            .any(|k| k.contains(&authority_hex)),
        "TreeKEM catch-up was requested from the authority"
    );
    Ok(())
}

/// WHY (#1139): the #818 loop is sound on the joiner side — once the
/// authority's catch-up page [r+1, r+2] lands, r+1 applies state-only
/// before the Welcome, the queued r+2 replays gaplessly and J2 converges.
#[tokio::test]
async fn issue1139_catchup_page_converges_second_joiner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    deliver_j2_legacy_result(&s).await;
    assert_eq!(
        join_state(&s.j2, &s.group_key).await,
        "pending_authority_commit"
    );
    // The responder sends this page as ONE plain direct message
    // (`handle_treekem_catchup_request` → `send_direct_with_config`), but
    // even a single Home MemberAdded exceeds the DM budget — so on the
    // wire this page is never delivered today. Injected here to prove
    // the joiner half of the loop.
    let page = catchup_page(&s);
    let one_event = serde_json::to_vec(&TreeKemCatchupResponse {
        message_type: page.message_type.clone(),
        group_id: page.group_id.clone(),
        events: vec![s.add_j1.event.clone()],
        truncated: false,
    })?
    .len();
    assert!(
        one_event > crate::dm::MAX_PAYLOAD_BYTES,
        "a one-event Home catch-up page is {one_event} B; DM budget {}",
        crate::dm::MAX_PAYLOAD_BYTES
    );
    handle_treekem_catchup_response(&s.j2, &s.authority_id, true, page).await;
    assert_eq!(join_state(&s.j2, &s.group_key).await, "active");
    assert!(s.j2.treekem_groups.read().await.contains_key(&s.group_key));
    Ok(())
}

/// WHY (#1139): the ordering control — r+1 before r+2 converges with no
/// catch-up at all (the pre-Welcome state-only apply takes r+1).
#[tokio::test]
async fn issue1139_r1_before_own_result_converges() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    assert!(
        apply_named_group_metadata_event(&s.j2, s.add_j1.event.clone(), s.authority_id, true, None)
            .await
            .accepted,
        "r+1 applies state-only on the pre-Welcome stub"
    );
    deliver_j2_legacy_result(&s).await;
    assert_eq!(join_state(&s.j2, &s.group_key).await, "active");
    assert!(s.j2.treekem_groups.read().await.contains_key(&s.group_key));
    Ok(())
}

/// WHY (#1139): the self-sufficient contract — the fixed authority's join
/// result carries the intervening r+1 MemberAdded, which the joiner applies
/// through the ordinary path (state-only, pre-Welcome) before its own r+2,
/// so the result ALONE converges J2 with no catch-up round trip. Red
/// without `apply_join_result_intervening_events`; green with it.
#[tokio::test]
async fn issue1139_join_result_alone_converges_second_joiner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let JoinResultMessage::Result {
        intervening_events, ..
    } = &s.j2_result
    else {
        panic!("fixture serves a Result");
    };
    assert_eq!(
        intervening_events
            .iter()
            .filter_map(named_group_metadata_event_commit)
            .map(|c| c.state_hash.clone())
            .collect::<Vec<_>>(),
        vec![s.add_j1.commit.state_hash.clone()],
        "the authority serves exactly the r+1 MemberAdded"
    );
    deliver_j2_result(&s).await;
    assert_eq!(join_state(&s.j2, &s.group_key).await, "active");
    assert!(s.j2.treekem_groups.read().await.contains_key(&s.group_key));
    assert!(
        s.j2.treekem_catchup_throttle.read().await.is_empty(),
        "converged without any catch-up round trip"
    );
    // Idempotent: the poll may re-deliver the same result.
    deliver_j2_result(&s).await;
    assert_eq!(join_state(&s.j2, &s.group_key).await, "active");
    Ok(())
}

/// WHY (#1139, mixed version): the field is additive. A legacy result
/// (no key) decodes to an empty list, and an empty list is omitted on the
/// wire, so a fixed authority talking to a legacy peer — and vice versa —
/// is byte-for-byte today's behaviour (the legacy path is pinned by
/// `issue1139_legacy_join_result_alone_leaves_second_joiner_pending`).
#[tokio::test]
async fn issue1139_intervening_events_field_is_additive_on_the_wire() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let legacy_wire = serde_json::to_value(&s.j2_legacy_result)?;
    assert!(
        legacy_wire.get("intervening_events").is_none(),
        "an empty list is omitted: a fixed authority with nothing to add sends the legacy shape"
    );
    let decoded: JoinResultMessage = serde_json::from_value(legacy_wire)?;
    assert!(matches!(
        decoded,
        JoinResultMessage::Result { ref intervening_events, .. } if intervening_events.is_empty()
    ));
    let new_wire = serde_json::to_value(&s.j2_result)?;
    assert_eq!(
        new_wire
            .get("intervening_events")
            .and_then(|v| v.as_array())
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

/// WHY (#1139, authority bounds): events are served only when they cover
/// the WHOLE gap, and only up to the cap — otherwise nothing, and the
/// joiner keeps today's path. A partial list would only fail later links.
#[tokio::test]
async fn issue1139_authority_serves_only_complete_bounded_gaps() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let keys = [s.stable_group_id.clone()];
    let r = s.add_j1.commit.revision - 1;
    let serve = |from: u64, terminal: u64| {
        super::super::intervening_membership_events(&s._authority, &keys, from, terminal)
    };
    assert_eq!(serve(r, r + 2).await.len(), 1, "complete one-link gap");
    assert!(
        serve(r + 1, r + 2).await.is_empty(),
        "no gap, nothing to carry"
    );
    assert!(
        serve(r + 2, r + 2).await.is_empty(),
        "joiner at or past the terminal"
    );
    assert!(
        serve(r.saturating_sub(1), r + 2).await.is_empty(),
        "r is not a logged membership event: the gap is not covered"
    );
    let cap = super::super::JOIN_RESULT_INTERVENING_EVENT_CAP as u64;
    assert!(serve(r, r + cap + 2).await.is_empty(), "over the cap");
    // A log that lost r+1 (e.g. the authority restarted) serves nothing.
    s._authority.treekem_event_log.write().await.clear();
    assert!(serve(r, r + 2).await.is_empty());
    Ok(())
}

/// WHY (#1139, joiner bounds): the joiner applies carried events only for
/// a CURRENT bound attempt, only for the same group and only up to the
/// cap. Anything else leaves J2 exactly where today's path leaves it.
#[tokio::test]
async fn issue1139_joiner_ignores_stale_foreign_or_oversized_carries() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let revision = |s: &BackToBack| {
        let j2 = Arc::clone(&s.j2);
        let key = s.group_key.clone();
        async move {
            j2.named_groups
                .read()
                .await
                .get(&key)
                .map(|i| i.state_revision)
        }
    };
    let base = revision(&s).await;

    // Stale attempt: rejected before any carried event is applied.
    super::super::handle_join_result_message_bound(
        &s.j2,
        &s.authority_id,
        true,
        s.j2_result.clone(),
        Some("attempt-dead"),
    )
    .await;
    assert_eq!(revision(&s).await, base, "stale attempt applies nothing");

    let with_events = |events: Vec<NamedGroupMetadataEvent>| match s.j2_result.clone() {
        JoinResultMessage::Result {
            event,
            chain,
            head_attestation,
            roster_certificates_b64,
            ..
        } => JoinResultMessage::Result {
            event,
            chain,
            head_attestation,
            roster_certificates_b64,
            intervening_events: events,
        },
        other => other,
    };
    // Over the cap: ignored wholesale.
    let cap = super::super::JOIN_RESULT_INTERVENING_EVENT_CAP;
    deliver_j2(&s, &with_events(vec![s.add_j1.event.clone(); cap + 1])).await;
    assert_eq!(revision(&s).await, base, "over-cap carry applies nothing");
    // Another group's event: ignored.
    let mut foreign = s.add_j1.event.clone();
    if let NamedGroupMetadataEvent::MemberAdded { group_id, .. } = &mut foreign {
        *group_id = "ee".repeat(32);
    }
    deliver_j2(&s, &with_events(vec![foreign])).await;
    assert_eq!(
        revision(&s).await,
        base,
        "foreign-group carry applies nothing"
    );
    assert_eq!(
        join_state(&s.j2, &s.group_key).await,
        "pending_authority_commit"
    );
    Ok(())
}

/// WHY (#1139): the live rc5 order. The standalone r+2 broadcast (no
/// served chain) is rejected SILENTLY — the #818 classifier returns at
/// its empty-chain guard, so there is no queue, no catch-up and no
/// WARN/INFO (exactly the live nuremberg log). A later r+1 still rescues
/// the join; in live it never did.
#[tokio::test]
async fn issue1139_standalone_r2_is_silent_then_r1_rescues() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let r2 =
        apply_named_group_metadata_event(&s.j2, s.add_j2.event.clone(), s.authority_id, true, None)
            .await;
    assert!(!r2.accepted);
    assert!(
        s.j2.treekem_pending_events
            .read()
            .await
            .get(&s.group_key)
            .is_none_or(|q| q.is_empty()),
        "standalone r+2: nothing queued"
    );
    assert!(
        s.j2.treekem_catchup_throttle.read().await.is_empty(),
        "standalone r+2: no catch-up requested"
    );
    assert!(
        apply_named_group_metadata_event(&s.j2, s.add_j1.event.clone(), s.authority_id, true, None)
            .await
            .accepted
    );
    deliver_j2_legacy_result(&s).await;
    assert_eq!(join_state(&s.j2, &s.group_key).await, "active");
    assert!(s.j2.treekem_groups.read().await.contains_key(&s.group_key));
    Ok(())
}
