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
    identity_cert: Option<&x0x::identity::AgentCertificate>,
) -> Result<SealedAdd> {
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member = member_kp.agent_id();
    let member_hex = hex::encode(member.as_bytes());
    // The device's OWN identity certificate when known (production seals the
    // joiner's own certificate, so a later re-join presents the same digest);
    // otherwise a fresh owner-issued one.
    let cert = match identity_cert {
        Some(cert) => cert.clone(),
        None => x0x::identity::AgentCertificate::issue(owner, member_kp)?,
    };
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
        j1.agent.identity().agent_certificate(),
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
        j2.agent.identity().agent_certificate(),
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
        signed_by: None,
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
            signed_by: None,
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
        signed_by: None,
        target_member_id: None,
        target_member_key_package_b64: None,
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
            signed_by: None,
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
        signed_by: None,
        target_member_id: None,
        target_member_key_package_b64: None,
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
            signed_by: None,
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

fn result_with_events(s: &BackToBack, events: Vec<NamedGroupMetadataEvent>) -> JoinResultMessage {
    match s.j2_result.clone() {
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
            signed_by: None,
        },
        other => other,
    }
}

/// A copy of r+1's event with its commit revision and group rewritten —
/// a structural probe for the preflight only (its signature is stale, so
/// the ordinary apply would refuse it anyway).
fn probe_event(s: &BackToBack, revision: u64, group: Option<&str>) -> NamedGroupMetadataEvent {
    let mut event = s.add_j1.event.clone();
    if let NamedGroupMetadataEvent::MemberAdded {
        group_id, commit, ..
    } = &mut event
    {
        if let Some(group) = group {
            *group_id = group.to_string();
        }
        if let Some(commit) = commit.as_mut() {
            commit.revision = revision;
        }
    }
    event
}

async fn j2_revision(s: &BackToBack) -> Option<u64> {
    s.j2.named_groups
        .read()
        .await
        .get(&s.group_key)
        .map(|i| i.state_revision)
}

/// WHY (#1139 review r1 P2-2): the joiner validates the WHOLE carried list
/// before any mutation — kind, group, unique contiguous revisions ending
/// at terminal−1 and reaching the stub. Pure function, every refusal arm.
#[tokio::test]
async fn issue1139_preflight_rejects_malformed_lists() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let g = s.stable_group_id.as_str();
    let r1 = s.add_j1.commit.revision;
    let local = r1 - 1;
    let pre = |local: u64, terminal: u64, events: Vec<NamedGroupMetadataEvent>| {
        super::super::preflight_join_result_intervening_events(g, local, terminal, events)
            .map(|v| v.into_iter().map(|(r, _)| r).collect::<Vec<_>>())
    };
    assert_eq!(
        pre(local, r1 + 1, vec![s.add_j1.event.clone()]),
        Some(vec![r1])
    );
    // Gap: r+1 and r+3 carried for terminal r+4 (r+2 missing).
    assert_eq!(
        pre(
            local,
            r1 + 3,
            vec![probe_event(&s, r1, None), probe_event(&s, r1 + 2, None)]
        ),
        None
    );
    // Duplicate revision.
    assert_eq!(
        pre(
            local,
            r1 + 1,
            vec![s.add_j1.event.clone(), probe_event(&s, r1, None)]
        ),
        None
    );
    // A foreign-group entry LATER in an otherwise contiguous list.
    assert_eq!(
        pre(
            local,
            r1 + 2,
            vec![
                s.add_j1.event.clone(),
                probe_event(&s, r1 + 1, Some(&"ee".repeat(32)))
            ]
        ),
        None
    );
    // At or beyond the terminal.
    assert_eq!(pre(local, r1, vec![s.add_j1.event.clone()]), None);
    // Does not reach the stub (first link above local+1).
    assert_eq!(
        pre(local, r1 + 2, vec![probe_event(&s, r1 + 1, None)]),
        None
    );
    // A MemberAdded without a commit (nothing to order or verify).
    let mut uncommitted = s.add_j1.event.clone();
    if let NamedGroupMetadataEvent::MemberAdded { commit, .. } = &mut uncommitted {
        *commit = None;
    }
    assert_eq!(pre(local, r1 + 1, vec![uncommitted]), None);
    // Over the cap.
    let cap = super::super::JOIN_RESULT_INTERVENING_EVENT_CAP;
    assert_eq!(
        pre(local, r1 + 1, vec![s.add_j1.event.clone(); cap + 1]),
        None
    );
    Ok(())
}

/// WHY (#1139 review r1 P2-2): a list whose VALID first link is followed by
/// a malformed entry is rejected before anything applies — the valid r+1
/// prefix must not land.
#[tokio::test]
async fn issue1139_malformed_carry_applies_no_prefix() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let base = j2_revision(&s).await;
    let r1 = s.add_j1.commit.revision;
    let foreign_dup = probe_event(&s, r1, Some(&"ee".repeat(32)));
    deliver_j2(
        &s,
        &result_with_events(&s, vec![s.add_j1.event.clone(), foreign_dup]),
    )
    .await;
    assert_eq!(
        j2_revision(&s).await,
        base,
        "the valid r+1 prefix was not applied"
    );
    assert_eq!(
        join_state(&s.j2, &s.group_key).await,
        "pending_authority_commit"
    );
    Ok(())
}

/// WHY (#1139 review r1 P2-1): carried events apply ONLY for a bound
/// attempt. An unbound delivery of the same result mutates nothing
/// through the carry.
#[tokio::test]
async fn issue1139_unbound_result_does_not_apply_carry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let base = j2_revision(&s).await;
    super::super::handle_join_result_message_bound(
        &s.j2,
        &s.authority_id,
        true,
        s.j2_result.clone(),
        None,
    )
    .await;
    assert_eq!(j2_revision(&s).await, base, "unbound carry applied nothing");
    Ok(())
}

/// WHY (#1139 review r1 P2-3): the authority attaches the carry only to a
/// result the joiner can pull as a control blob (the FetchRequest blob-path
/// predicate), so a legacy joiner's inline result can never be pushed past
/// the DM budget and dropped.
#[test]
fn issue1139_carry_only_for_blob_capable_bound_fetches() {
    use super::super::join_result_carry_allowed as allowed;
    assert!(allowed(true, true, true));
    assert!(
        !allowed(true, false, true),
        "legacy joiner: no blob capability"
    );
    assert!(!allowed(true, true, false), "no attempt binding");
    assert!(!allowed(false, true, true), "unverified fetch");
}

/// WHY (#1139 review r2): the authority checks revision conflicts across
/// EVERY logged commit in the gap before selecting MemberAdded events. A
/// competing MemberRemoved at r+1 (a different commit hash) must suppress
/// the carry whichever order it was logged in, and a gap revision held
/// only by a non-MemberAdded commit must too.
#[tokio::test]
async fn issue1139_authority_competing_commit_in_gap_suppresses_carry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let keys = [s.stable_group_id.clone()];
    let r1 = s.add_j1.commit.revision;
    let (from, terminal) = (r1 - 1, r1 + 1);
    let mut competing = s.add_j1.commit.clone();
    competing.state_hash = "ff".repeat(32);
    let removed = NamedGroupMetadataEvent::MemberRemoved {
        group_id: s.stable_group_id.clone(),
        revision: r1,
        actor: hex::encode(s.authority_id.as_bytes()),
        agent_id: s.add_j1.member_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(competing),
    };
    let serve =
        || super::super::intervening_membership_events(&s._authority, &keys, from, terminal);
    assert_eq!(serve().await.len(), 1, "control: the clean gap carries r+1");
    let key = s.stable_group_id.clone();
    let set_log = |events: Vec<NamedGroupMetadataEvent>| {
        let authority = Arc::clone(&s._authority);
        let key = key.clone();
        async move {
            authority
                .treekem_event_log
                .write()
                .await
                .insert(key, events.into_iter().collect());
        }
    };
    set_log(vec![
        s.add_j1.event.clone(),
        removed.clone(),
        s.add_j2.event.clone(),
    ])
    .await;
    assert!(
        serve().await.is_empty(),
        "MemberAdded then competing MemberRemoved"
    );
    set_log(vec![
        removed.clone(),
        s.add_j1.event.clone(),
        s.add_j2.event.clone(),
    ])
    .await;
    assert!(
        serve().await.is_empty(),
        "competing MemberRemoved then MemberAdded"
    );
    set_log(vec![removed, s.add_j2.event.clone()]).await;
    assert!(
        serve().await.is_empty(),
        "the gap revision holds only a removal"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// D39(A) regression (#1148, ruling D43): a Home device whose join timed out
// AFTER a state-only intermediate apply (the ADR 0106 carry) keeps a durable
// `not_member` row. The owner removes it (`x0x group remove-member`) and
// re-invites it; the device must converge `active` WITH its TreeKEM group.
// Each join is a FAITHFUL round trip: the device's NEW MemberJoined goes
// through the owner device's real apply, and whatever it stages is served
// back as its FetchRequest arm would (the staged Welcome is inlined — the
// in-process stand-in for the control-blob pull). Red without #1148
// (probe PR #1151), green with it (probe PR #1152).
// ---------------------------------------------------------------------------
async fn wa_state(joiner: &Arc<AppState>, group_key: &str) -> &'static str {
    let info = joiner.named_groups.read().await.get(group_key).cloned();
    match info {
        Some(info) => {
            let local = hex::encode(joiner.agent.agent_id().as_bytes());
            local_join_membership_state(joiner, &info, &local).await
        }
        None => "no_row",
    }
}

struct WaJoin {
    status: StatusCode,
    body: String,
    new_attempt: bool,
    authority_accepted: bool,
    staged: bool,
    final_state: &'static str,
    treekem: bool,
}

impl std::fmt::Display for WaJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status={} new_attempt={} authority_accepted_member_joined={} staged={} final={} treekem={} body={}",
            self.status, self.new_attempt, self.authority_accepted, self.staged,
            self.final_state, self.treekem, self.body
        )
    }
}

/// Mint a fresh invite for J2 (`x0x` home seat / mint), join through the
/// real route, then the faithful authority round trip.
async fn wa_fresh_invite_round_trip(s: &BackToBack) -> Result<WaJoin> {
    wa_fresh_invite_round_trip_on(s, &s.j2).await
}

async fn wa_fresh_invite_round_trip_on(s: &BackToBack, joiner: &Arc<AppState>) -> Result<WaJoin> {
    let j2_hex = hex::encode(joiner.agent.agent_id().as_bytes());
    let before: Option<String> = {
        let key = join_result_key(&s.stable_group_id, &j2_hex);
        joiner
            .pending_join_attempts
            .lock()
            .expect("attempt registry")
            .get(&key)
            .map(|a| a.attempt_id.clone())
    };
    let (_invite, link) = mint_invite_transaction(
        &s._authority,
        &s.group_key,
        3_600,
        Some(joiner.agent.agent_id()),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint fresh invite: {e:?}"))?;
    let owner_pin = hex::encode(
        s._authority
            .agent
            .identity()
            .user_keypair()
            .expect("owned")
            .user_id()
            .as_bytes(),
    );
    let response = join_group_via_invite(
        State(Arc::clone(joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(owner_pin),
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body =
        String::from_utf8_lossy(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)
            .to_string();
    let key = join_result_key(&s.stable_group_id, &j2_hex);
    let attempt = joiner
        .pending_join_attempts
        .lock()
        .expect("attempt registry")
        .get(&key)
        .filter(|a| Some(&a.attempt_id) != before.as_ref())
        .map(|a| {
            (
                a.attempt_id.clone(),
                a.stored_resend.as_ref().map(|r| r.event.clone()),
            )
        });
    let mut out = WaJoin {
        status,
        body,
        new_attempt: attempt.is_some(),
        authority_accepted: false,
        staged: false,
        final_state: "unknown",
        treekem: false,
    };
    if let Some((attempt_id, Some(member_joined))) = attempt {
        s._authority.pending_join_results.write().await.clear();
        out.authority_accepted = apply_named_group_metadata_event(
            &s._authority,
            member_joined,
            joiner.agent.agent_id(),
            true,
            None,
        )
        .await
        .accepted;
        let staged = s
            ._authority
            .pending_join_results
            .read()
            .await
            .get(&key)
            .map(|p| (p.event.clone(), p.head_attestation.clone()));
        out.staged = staged.is_some();
        if !out.authority_accepted {
            let counters = super::group_counters_for_test(&s._authority, &s.stable_group_id).await;
            out.body = format!("{} authority_counters={counters:?}", out.body);
        }
        if let Some((mut event, head_attestation)) = staged {
            // In-process transport stand-in: the owner device sends the
            // Welcome by reference (control-blob pull over the network);
            // inline the staged bytes exactly as the R19 tests do.
            if let NamedGroupMetadataEvent::MemberAdded {
                treekem_welcome_b64,
                welcome_ref,
                ..
            } = &mut event
            {
                if let Some(reference) = welcome_ref.take() {
                    let welcomes = s._authority.pending_welcomes.read().await;
                    if let Some(welcome) = welcomes.get(&reference.welcome_id) {
                        *treekem_welcome_b64 = Some(BASE64.encode(&welcome.bytes));
                    } else {
                        *welcome_ref = Some(reference);
                    }
                }
            }
            let from = joiner
                .named_groups
                .read()
                .await
                .get(&s.group_key)
                .map(|i| i.state_revision)
                .unwrap_or_default();
            let terminal = named_group_metadata_event_commit(&event).map(|c| c.revision);
            let info = s
                ._authority
                .named_groups
                .read()
                .await
                .get(&s.group_key)
                .cloned()
                .expect("authority group");
            let (chain, intervening_events) = match terminal {
                Some(terminal) => (
                    intervening_chain_from(&info, from, terminal),
                    // Mirrors the authority's serve, including the re-key link.
                    super::super::intervening_membership_events_for(
                        &s._authority,
                        std::slice::from_ref(&s.stable_group_id),
                        from,
                        terminal,
                        super::super::join_result_rekey_member(
                            &event,
                            &hex::encode(joiner.agent.agent_id().as_bytes()),
                        ),
                    )
                    .await,
                ),
                None => (Vec::new(), Vec::new()),
            };
            super::super::handle_join_result_message_bound(
                joiner,
                &s.authority_id,
                true,
                JoinResultMessage::Result {
                    event: Box::new(event),
                    chain,
                    head_attestation: head_attestation.map(Box::new),
                    roster_certificates_b64: Vec::new(),
                    intervening_events,
                    signed_by: None,
                },
                Some(attempt_id.as_str()),
            )
            .await;
        }
    }
    out.final_state = wa_state(joiner, &s.group_key).await;
    out.treekem = joiner
        .treekem_groups
        .read()
        .await
        .contains_key(&s.group_key);
    Ok(out)
}

/// Stuck state A: the carry applied r+1 state-only, J2's own seat never
/// landed, the attempt timed out → durable `not_member` row.
async fn wa_stuck_not_member(s: &BackToBack) -> Result<()> {
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    super::super::apply_join_result_intervening_events(
        &s.j2,
        &s.authority_id,
        true,
        &s.stable_group_id,
        Some(s.add_j2.commit.revision),
        Some(s.j2_attempt.as_str()),
        vec![s.add_j1.event.clone()],
    )
    .await;
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable_group_id,
        &j2_hex,
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    assert_eq!(
        wa_state(&s.j2, &s.group_key).await,
        "not_member",
        "stuck precondition"
    );
    Ok(())
}

/// Stuck state B: the timed-out join (no carry) then the documented fresh
/// invite → keyless `active` (the authority rejects the re-join, #1150).
async fn wa_stuck_keyless(s: &BackToBack) -> Result<WaJoin> {
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable_group_id,
        &j2_hex,
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    wa_fresh_invite_round_trip(s).await
}

/// The owner removes J2 (`x0x group remove-member <group> <agent>` =
/// `DELETE /groups/:id/members/:agent_id`); optionally the resulting
/// MemberRemoved reaches J2. Returns J2's local state afterwards.
async fn wa_owner_removes_j2(s: &BackToBack, deliver: bool) -> Result<&'static str> {
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    s._authority
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish hook")
        .clear();
    let response = remove_named_group_member(
        State(Arc::clone(&s._authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), j2_hex.clone())),
    )
    .await
    .into_response();
    let status = response.status();
    let body =
        String::from_utf8_lossy(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)
            .to_string();
    anyhow::ensure!(status.is_success(), "owner remove-member: {status} {body}");
    if deliver {
        let removed = s
            ._authority
            .named_group_test_recorders
            .publish_bytes
            .lock()
            .expect("publish hook")
            .iter()
            .filter_map(|(_t, b)| serde_json::from_slice::<NamedGroupMetadataEvent>(b).ok())
            .find(|e| matches!(e, NamedGroupMetadataEvent::MemberRemoved { agent_id, .. } if *agent_id == j2_hex));
        if let Some(event) = removed {
            apply_named_group_metadata_event(&s.j2, event, s.authority_id, true, None).await;
        }
    }
    Ok(wa_state(&s.j2, &s.group_key).await)
}

fn wa_assert_recovered(ctx: &str, r: &WaJoin) {
    assert!(
        r.new_attempt && r.final_state == "active" && r.treekem,
        "owner remove-member + fresh invite did NOT recover with keys [{ctx}]: {r}"
    );
}

/// The authority's live tree encrypts after the re-key; `joiner` must
/// decrypt it with the tree its Welcome installed.
async fn wa_decrypts_post_rekey(s: &BackToBack, joiner: &Arc<AppState>) -> Result<bool> {
    let tree = |state: &Arc<AppState>| {
        let state = Arc::clone(state);
        let keys = [s.group_key.clone(), s.stable_group_id.clone()];
        async move {
            let trees = state.treekem_groups.read().await;
            keys.iter().find_map(|k| trees.get(k).cloned())
        }
    };
    let authority = tree(&s._authority).await.context("authority tree")?;
    let Some(device) = tree(joiner).await else {
        return Ok(false);
    };
    let plaintext = b"after the returning-member re-key".to_vec();
    let ciphertext = authority.lock().await.encrypt_message(&plaintext)?;
    let opened = device.lock().await.decrypt_message(&ciphertext);
    Ok(opened.is_ok_and(|bytes| bytes == plaintext))
}

/// #1150 on this fork: after a timed-out join left the device keyless
/// `active`, a fresh invite alone re-keys it. The authority's
/// returning-member re-key accepts the re-join MemberJoined (a fresh
/// KeyPackage from an Active member) and commits remove + add; the join
/// result carries the device's own removal as the last #1139 link, so the
/// device chains from its revision to the add, installs the Welcome and
/// reads traffic sealed after the re-key.
#[tokio::test]
async fn d39_1150_fresh_invite_alone_rekeys_the_keyless_device() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let r = wa_stuck_keyless(&s).await?;
    assert!(
        r.new_attempt && r.authority_accepted && r.staged && r.final_state == "active" && r.treekem,
        "#1150: the fresh invite must re-key the keyless device end to end: {r}"
    );
    assert!(
        wa_decrypts_post_rekey(&s, &s.j2).await?,
        "#1150: the re-keyed device must decrypt a post-re-key message"
    );
    Ok(())
}

/// Reinstall: a device that held keys loses every local trace of the group
/// (app data cleared, identity kept) while the authority still seats it.
/// A fresh invite alone must re-key it: the new stub starts at the invite's
/// base, the result carries the device's removal, and the device ends
/// `active` with a tree that decrypts post-re-key traffic.
#[tokio::test]
async fn reinstalled_device_recovers_keys_from_a_fresh_invite() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    let first = wa_stuck_keyless(&s).await?;
    anyhow::ensure!(
        first.treekem,
        "precondition: the device holds keys: {first}"
    );

    let aliases = [s.group_key.clone(), s.stable_group_id.clone()];
    let removed = persist_named_groups_mutation(&s.j2, |groups| {
        let mut any = false;
        for alias in &aliases {
            any |= groups.remove(alias).is_some();
        }
        any
    })
    .await;
    anyhow::ensure!(
        matches!(removed, Ok(AtomicWriteOutcome::Durable)),
        "reinstall wipe persisted"
    );
    for alias in &aliases {
        s.j2.treekem_groups.write().await.remove(alias);
    }
    wipe_local_group_crypto_material(
        &s.j2,
        &s.group_key,
        Some(s.stable_group_id.as_str()),
        "reinstall_fixture",
    )
    .await;
    assert_eq!(wa_state(&s.j2, &s.group_key).await, "no_row");

    let r = wa_fresh_invite_round_trip(&s).await?;
    assert!(
        r.new_attempt && r.authority_accepted && r.final_state == "active" && r.treekem,
        "a reinstalled device must recover with keys from a fresh invite: {r}"
    );
    assert!(
        wa_decrypts_post_rekey(&s, &s.j2).await?,
        "the reinstalled device must decrypt a post-re-key message"
    );
    Ok(())
}

/// The device's join timed out with no state-only apply (no carry): the
/// finalizer removes the pending stub, so no row remains.
async fn d39_timed_out_without_carry(s: &BackToBack) -> &'static str {
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable_group_id,
        &j2_hex,
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    wa_state(&s.j2, &s.group_key).await
}

async fn d39_not_member_remove_reinvite(deliver_removal: bool) -> Result<(String, WaJoin)> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    wa_stuck_not_member(&s).await?;
    let after_removal = wa_owner_removes_j2(&s, deliver_removal).await?;
    let r = wa_fresh_invite_round_trip(&s).await?;
    Ok((
        format!(
            "from=not_member removal_delivered={deliver_removal} j2_after_removal={after_removal}"
        ),
        r,
    ))
}

/// D39(A): stuck `not_member` → the owner removes the device (the removal
/// reaches it) → fresh invite → `active` WITH keys. Red on eb4c6b7: the
/// leftover row answered the invite `ok:true, join_state:"not_member"` and
/// started no attempt.
#[tokio::test]
async fn d39_a_not_member_owner_removes_delivered_then_fresh_invite_recovers_keys() -> Result<()> {
    let (ctx, r) = d39_not_member_remove_reinvite(true).await?;
    wa_assert_recovered(&ctx, &r);
    Ok(())
}

/// D39(A): the same with the device OFFLINE for the removal (its leftover
/// row stays `not_member`) — the fresh invite still recovers it with keys.
#[tokio::test]
async fn d39_a_not_member_owner_removes_undelivered_then_fresh_invite_recovers_keys() -> Result<()>
{
    let (ctx, r) = d39_not_member_remove_reinvite(false).await?;
    wa_assert_recovered(&ctx, &r);
    Ok(())
}

/// `x0x group leave <id>` (`DELETE /groups/:id`) for the non-member row.
/// This fork admits it for the DURABLE owner only, as the #376 local-only
/// drop (TreeKEM state of a group the node no longer belongs to is wiped,
/// nothing is published, no roster changes); a session bearer is still
/// refused (`local_only_drop_refuses_a_session_bearer`).
#[tokio::test]
async fn d39_a_leave_is_a_local_only_drop_for_a_not_member_row() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    wa_stuck_not_member(&s).await?;
    let response = leave_group(
        State(Arc::clone(&s.j2)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(s.group_key.clone()),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "#376: the durable owner may drop a not-member row locally"
    );
    assert_eq!(
        wa_state(&s.j2, &s.group_key).await,
        "no_row",
        "the local-only drop removes the row"
    );
    Ok(())
}

/// Review r1 P1-1: a BANNED device's row is never cleared — a fresh invite
/// must not restore it (no new attempt, the ban stays).
#[tokio::test]
async fn d39_a_banned_row_is_not_cleared_and_does_not_rejoin() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    wa_stuck_not_member(&s).await?;
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    s.j2.named_groups
        .write()
        .await
        .get_mut(&s.group_key)
        .expect("row")
        .ban_member(&j2_hex, None);
    let r = wa_fresh_invite_round_trip(&s).await?;
    assert!(
        !r.new_attempt,
        "a banned row must not start a join attempt: {r}"
    );
    let groups = s.j2.named_groups.read().await;
    assert!(
        groups
            .get(&s.group_key)
            .expect("the banned row is kept")
            .is_banned(&j2_hex),
        "the ban survives the retry"
    );
    Ok(())
}

/// Review r1 P1-2: a fork-quarantined remnant keeps its containment — the
/// retry is refused with 409 `fork_quarantined` and the evidence survives.
#[tokio::test]
async fn d39_a_quarantined_row_is_refused_and_keeps_evidence() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    wa_stuck_not_member(&s).await?;
    let evidence = x0x::groups::ForkEvidence {
        revision: 1,
        state_hash: "ab".repeat(32),
        committed_by: "cd".repeat(32),
        observed_at_ms: 1,
    };
    s.j2.named_groups
        .write()
        .await
        .get_mut(&s.group_key)
        .and_then(|row| row.invite_lineage.as_mut())
        .expect("lineage")
        .fork_evidence = Some(evidence.clone());
    let r = wa_fresh_invite_round_trip(&s).await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{r}");
    assert!(r.body.contains("fork_quarantined"), "{r}");
    assert!(!r.new_attempt, "{r}");
    let groups = s.j2.named_groups.read().await;
    let lineage = groups
        .get(&s.group_key)
        .and_then(|row| row.invite_lineage.as_ref())
        .expect("the quarantined row and its lineage are kept");
    assert_eq!(lineage.fork_evidence.as_ref(), Some(&evidence));
    Ok(())
}

/// Codex r2 scenario (#1149): the owner device ADMITTED J2 (its seat is
/// sealed), mints an invite whose base already holds J2's ACTIVE seat, then
/// BANS J2; J2 observes neither and joins with that invite.
async fn d39_r2_join_with_pre_ban_seated_invite(
    s: &BackToBack,
    carry: bool,
) -> Result<&'static str> {
    let j2_hex = hex::encode(s.j2.agent.agent_id().as_bytes());
    if carry {
        wa_stuck_not_member(s).await?;
    } else {
        assert_eq!(d39_timed_out_without_carry(s).await, "no_row");
    }
    let (_invite, link) = mint_invite_transaction(
        &s._authority,
        &s.group_key,
        3_600,
        Some(s.j2.agent.agent_id()),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint invite: {e:?}"))?;
    s._authority
        .named_groups
        .write()
        .await
        .get_mut(&s.group_key)
        .expect("authority group")
        .ban_member(&j2_hex, None);
    let owner_pin = hex::encode(
        s._authority
            .agent
            .identity()
            .user_keypair()
            .expect("owned")
            .user_id()
            .as_bytes(),
    );
    let response = join_group_via_invite(
        State(Arc::clone(&s.j2)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(owner_pin),
        }),
    )
    .await
    .into_response();
    assert!(
        response.status().is_success(),
        "join route: {}",
        response.status()
    );
    Ok(wa_state(&s.j2, &s.group_key).await)
}

/// Characterization (Codex r2, PRE-EXISTING since eb4c6b7, tracked as
/// #1149): a device with NO local row that joins with a stale invite whose
/// base seats it reports local `active` from the snapshot alone, although
/// the owner device banned it since. Flip when #1149 is fixed.
#[tokio::test]
async fn d39_r2_preexisting_seated_invite_without_row_reports_active() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    assert_eq!(
        d39_r2_join_with_pre_ban_seated_invite(&s, false).await?,
        "active"
    );
    Ok(())
}

/// Characterization (Codex r2, #1149): the #1148 recovery routes the stuck
/// remnant onto exactly that pre-existing path — same input, same `active`.
/// Flip together with the test above when #1149 is fixed.
#[tokio::test]
async fn d39_r2_recovered_remnant_takes_the_same_seated_invite_path() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    assert_eq!(
        d39_r2_join_with_pre_ban_seated_invite(&s, true).await?,
        "active"
    );
    Ok(())
}

/// The re-key link is the ONLY non-`MemberAdded` shape the carry admits: a
/// removal of the member the terminal re-seats, by someone else, as the
/// last link. A removal of anybody else, a self-leave, a removal that is
/// not the last link, or any removal without a re-seated member is refused
/// exactly as upstream refuses it.
#[test]
fn carry_admits_only_the_rekey_removal_of_the_reseated_member() {
    let commit = |revision: u64| x0x::groups::GroupStateCommit {
        group_id: "g".to_string(),
        revision,
        prev_state_hash: None,
        roster_root: String::new(),
        policy_hash: String::new(),
        public_meta_hash: String::new(),
        security_binding: None,
        state_hash: String::new(),
        withdrawn: false,
        committed_by: "aa".repeat(32),
        committed_at: 1,
        signer_public_key: String::new(),
        signature: String::new(),
    };
    let removal =
        |actor: &str, member: &str, revision: u64| NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".to_string(),
            revision,
            actor: actor.to_string(),
            agent_id: member.to_string(),
            treekem_commit_b64: Some("c".to_string()),
            treekem_epoch: Some(revision),
            secret_epoch: None,
            commit: Some(commit(revision)),
        };
    let admin = "aa".repeat(32);
    let device = "bb".repeat(32);
    let other = "cc".repeat(32);
    let preflight = |events: Vec<NamedGroupMetadataEvent>, member: Option<&str>| {
        super::super::preflight_join_result_intervening_events_for("g", 4, 6, events, member)
            .is_some()
    };
    assert!(preflight(vec![removal(&admin, &device, 5)], Some(&device)));
    assert!(!preflight(vec![removal(&admin, &device, 5)], None));
    assert!(!preflight(vec![removal(&admin, &other, 5)], Some(&device)));
    assert!(!preflight(
        vec![removal(&device, &device, 5)],
        Some(&device)
    ));
    assert!(super::super::preflight_join_result_intervening_events_for(
        "g",
        3,
        6,
        vec![removal(&admin, &device, 4), removal(&admin, &device, 5)],
        Some(&device),
    )
    .is_none());
}

/// The #376 local-only drop never clears a fork-quarantined row: the durable
/// owner's leave answers 409 `fork_quarantined`, and the row with its fork
/// evidence stays for the audited quarantine clear.
#[tokio::test]
async fn local_only_drop_refuses_a_fork_quarantined_row() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build_back_to_back(dir.path()).await?;
    wa_stuck_not_member(&s).await?;
    let evidence = x0x::groups::ForkEvidence {
        revision: 1,
        state_hash: "ab".repeat(32),
        committed_by: "cd".repeat(32),
        observed_at_ms: 1,
    };
    s.j2.named_groups
        .write()
        .await
        .get_mut(&s.group_key)
        .and_then(|row| row.invite_lineage.as_mut())
        .expect("lineage")
        .fork_evidence = Some(evidence.clone());
    let response = leave_group(
        State(Arc::clone(&s.j2)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(s.group_key.clone()),
    )
    .await
    .into_response();
    let status = response.status();
    let body =
        String::from_utf8_lossy(&axum::body::to_bytes(response.into_body(), usize::MAX).await?)
            .to_string();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("fork_quarantined"), "{body}");
    let groups = s.j2.named_groups.read().await;
    let lineage = groups
        .get(&s.group_key)
        .and_then(|row| row.invite_lineage.as_ref())
        .expect("the quarantined row is kept");
    assert_eq!(lineage.fork_evidence.as_ref(), Some(&evidence));
    Ok(())
}
