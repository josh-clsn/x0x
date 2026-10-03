use super::*;

// ADR 0107 (0088 slice S8 (a), ruling D55): a Home device whose join timed out
// AFTER the authority sealed its add, but before it installed its Welcome,
// keeps a durable `not_member` carry remnant (#1148's `UnseatedJoinRemnant`).
// A fresh invite whose verified base seats the device must RE-ARM that
// remnant: keep the pre-seat revision, register a new bound attempt and
// re-fetch the authority's STILL-STAGED original join result and Welcome.
// The authority serves those artifacts only to a requester that is Active,
// not banned and certificate-valid on the CURRENT committed roster.
//
// Every fixture here is in-process: agents are built without a network
// config (no `join_network`, no bootstrap peers), so every transport send
// fails locally. The authority's serve decision is read from the test-only
// `join_result_serves` witness (FetchRequest arm) and from the Welcome
// stream registry (`pending_welcome_streams`).

const OWNER_SEED: [u8; 32] = [0x07; 32];

fn hex_of(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// One of the owner's own devices (the owner key certifies it), in-process.
async fn device(
    dir: &std::path::Path,
    name: &str,
    kp: x0x::identity::AgentKeypair,
) -> anyhow::Result<Arc<AppState>> {
    let jdir = dir.join(name);
    tokio::fs::create_dir_all(&jdir).await?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.join("machine.key"))
            .with_agent_key(kp)
            .with_agent_cert_path(jdir.join("agent.cert"))
            .with_user_key(x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.join("contacts.json"))
            .build()
            .await?,
    );
    secure_endpoint_test_state_at(&jdir, agent).await
}

fn keypair(bytes: &(Vec<u8>, Vec<u8>)) -> anyhow::Result<x0x::identity::AgentKeypair> {
    Ok(x0x::identity::AgentKeypair::from_bytes(&bytes.0, &bytes.1)?)
}

fn owner_pin_of(authority: &AppState) -> String {
    hex::encode(
        authority
            .agent
            .identity()
            .user_keypair()
            .expect("owned authority")
            .user_id()
            .as_bytes(),
    )
}

/// A fresh invite minted by the authority (the original sealer) for `joiner`.
async fn mint_for(
    authority: &AppState,
    group_key: &str,
    joiner: &AppState,
) -> anyhow::Result<String> {
    let (_invite, link) = mint_invite_transaction(
        authority,
        group_key,
        3_600,
        Some(joiner.agent.agent_id()),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint invite: {e:?}"))?;
    Ok(link)
}

/// Run the REAL join route; `home_pin` selects Home mode.
async fn join(
    joiner: &Arc<AppState>,
    link: String,
    home_pin: Option<String>,
) -> anyhow::Result<(StatusCode, serde_json::Value)> {
    let response = join_group_via_invite(
        State(Arc::clone(joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: home_pin.as_ref().map(|_| "home".to_string()),
            expected_owner_user_id: home_pin,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, body))
}

fn join_state_of(body: &serde_json::Value) -> &str {
    body.get("join_state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>")
}

/// The joiner's live attempt id and its stored `MemberJoined`, if any.
fn attempt_of(
    joiner: &AppState,
    stable: &str,
) -> Option<(String, Option<NamedGroupMetadataEvent>)> {
    joiner
        .pending_join_attempts
        .lock()
        .expect("attempt registry")
        .get(&join_result_key(stable, &hex_of(joiner)))
        .map(|a| {
            (
                a.attempt_id.clone(),
                a.stored_resend.as_ref().map(|r| r.event.clone()),
            )
        })
}

async fn staged(
    authority: &AppState,
    stable: &str,
    member_hex: &str,
) -> Option<super::super::PendingJoinResult> {
    authority
        .pending_join_results
        .read()
        .await
        .get(&join_result_key(stable, member_hex))
        .cloned()
}

fn welcome_id_of(event: &NamedGroupMetadataEvent) -> Option<String> {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(reference),
            ..
        } => Some(reference.welcome_id.clone()),
        _ => None,
    }
}

fn revision_of(event: &NamedGroupMetadataEvent) -> Option<u64> {
    named_group_metadata_event_commit(event).map(|c| c.revision)
}

async fn local_state(joiner: &AppState, group_key: &str) -> &'static str {
    let info = joiner.named_groups.read().await.get(group_key).cloned();
    match info {
        Some(info) => local_join_membership_state(joiner, &info, &hex_of(joiner)).await,
        None => "no_row",
    }
}

async fn keyed(joiner: &AppState, group_key: &str) -> bool {
    joiner.treekem_groups.read().await.contains_key(group_key)
}

/// The typed failed re-arm on the join-status surface: `timed_out`, with
/// the cause named.
fn assert_rearm_timed_out(joiner: &AppState, group_key: &str, ctx: &str) {
    let outcome = joiner
        .last_join_outcomes
        .lock()
        .expect("outcomes")
        .get(group_key)
        .map(|o| (o.outcome, o.reason));
    assert_eq!(
        outcome,
        Some(("timed_out", Some(super::super::JOIN_REARM_TIMEOUT_REASON))),
        "[{ctx}] a failed re-arm ends with the typed timed_out outcome and its cause"
    );
}

/// The authority's PRODUCTION `FetchRequest` arm for `joiner`; returns the
/// join result it decided to serve, if any.
pub(super) async fn serve_result(
    authority: &Arc<AppState>,
    joiner: &AppState,
    stable: &str,
    attempt: &str,
    from_revision: Option<u64>,
) -> Option<JoinResultMessage> {
    let member = hex_of(joiner);
    authority
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .clear();
    super::super::handle_join_result_message(
        authority,
        &joiner.agent.agent_id(),
        true,
        JoinResultMessage::FetchRequest {
            group_id: stable.to_string(),
            member_agent_id: member.clone(),
            from_revision,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: true,
            attempt_id: Some(attempt.to_string()),
        },
    )
    .await;
    let payload = authority
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .iter()
        .rev()
        .find(|(to, group, _)| *to == member && group == stable)
        .map(|(_, _, payload)| payload.clone());
    payload.and_then(|payload| serde_json::from_slice(&payload).ok())
}

/// The authority's PRODUCTION Welcome serve path for `joiner`; true when it
/// started a stream for the staged Welcome.
pub(super) async fn serve_welcome(
    authority: &Arc<AppState>,
    joiner: &AppState,
    stable: &str,
    welcome_id: &str,
) -> bool {
    let previous = authority
        .pending_welcome_streams
        .lock()
        .await
        .as_mut()
        .and_then(|streams| streams.remove(welcome_id));
    if let Some(previous) = previous {
        previous.abort();
        let _ = previous.await;
    }
    authority
        .pending_welcome_acks
        .write()
        .await
        .remove(welcome_id);
    super::super::handle_welcome_blob_message(
        authority,
        &joiner.agent.agent_id(),
        WelcomeBlobMessage::FetchRequest {
            group_id: stable.to_string(),
            welcome_id: welcome_id.to_string(),
        },
    )
    .await;
    authority
        .pending_welcome_streams
        .lock()
        .await
        .as_ref()
        .is_some_and(|streams| streams.contains_key(welcome_id))
}

/// In-process stand-in for the Welcome blob pull: inline the staged bytes
/// the authority's Welcome path just agreed to stream.
async fn with_inline_welcome(authority: &AppState, result: JoinResultMessage) -> JoinResultMessage {
    match result {
        JoinResultMessage::Result {
            mut event,
            chain,
            head_attestation,
            roster_certificates_b64,
            intervening_events,
        } => {
            if let NamedGroupMetadataEvent::MemberAdded {
                treekem_welcome_b64,
                welcome_ref,
                ..
            } = event.as_mut()
            {
                if let Some(reference) = welcome_ref.take() {
                    let bytes = authority
                        .pending_welcomes
                        .read()
                        .await
                        .get(&reference.welcome_id)
                        .map(|w| w.bytes.clone());
                    match bytes {
                        Some(bytes) => *treekem_welcome_b64 = Some(BASE64.encode(bytes)),
                        None => *welcome_ref = Some(reference),
                    }
                }
            }
            JoinResultMessage::Result {
                event,
                chain,
                head_attestation,
                roster_certificates_b64,
                intervening_events,
            }
        }
        other => other,
    }
}

async fn deliver(
    joiner: &Arc<AppState>,
    sender: &AgentId,
    result: JoinResultMessage,
    attempt: &str,
) {
    super::super::handle_join_result_message_bound(joiner, sender, true, result, Some(attempt))
        .await;
}

struct Fixture {
    dir: std::path::PathBuf,
    authority: Arc<AppState>,
    authority_id: AgentId,
    group_key: String,
    stable: String,
    /// The invite base both first invites carried (r).
    base: u64,
    j1: Arc<AppState>,
    j2: Arc<AppState>,
    j2_kp: (Vec<u8>, Vec<u8>),
    j1_attempt: String,
    j2_attempt: String,
    /// J1's sealed add at r+1, as the authority staged it.
    j1_add: NamedGroupMetadataEvent,
    /// J2's sealed add at r+2 (Welcome by reference), as staged.
    j2_add: NamedGroupMetadataEvent,
}

/// Two Home devices join through the REAL route with two invites minted from
/// the same base r; the authority seals both through its REAL `MemberJoined`
/// apply (r+1 for J1, r+2 for J2), staging each join result and Welcome.
async fn build(dir: &std::path::Path) -> anyhow::Result<Fixture> {
    let authority = super::super::super::home::tests::owned_state(dir, OWNER_SEED).await?;
    super::super::super::home::provision_home(&authority).await;
    let owner = authority
        .agent
        .identity()
        .user_keypair()
        .expect("owned Home")
        .user_id();
    let (_, home) = super::super::super::home::find_home(&authority, &owner)
        .await
        .expect("provisioned Home");
    let group_key = home.mls_group_id.clone();
    let stable = home.stable_group_id().to_string();
    let base = home.state_revision;

    let j1_kp = x0x::identity::AgentKeypair::generate()?;
    let j2_kp = x0x::identity::AgentKeypair::generate()?;
    let j2_bytes = j2_kp.to_bytes();
    let j1 = device(dir, "j1", j1_kp).await?;
    let j2 = device(dir, "j2", j2_kp).await?;
    let link1 = mint_for(&authority, &group_key, &j1).await?;
    let link2 = mint_for(&authority, &group_key, &j2).await?;
    let pin = owner_pin_of(&authority);
    for (joiner, link) in [(&j1, link1), (&j2, link2)] {
        let (status, body) = join(joiner, link, Some(pin.clone())).await?;
        anyhow::ensure!(
            status == StatusCode::OK && join_state_of(&body) == "pending_authority_commit",
            "first join: {status} {body}"
        );
    }
    let (j1_attempt, Some(j1_joined)) = attempt_of(&j1, &stable).expect("J1 attempt") else {
        anyhow::bail!("J1 stored no MemberJoined");
    };
    let (j2_attempt, Some(j2_joined)) = attempt_of(&j2, &stable).expect("J2 attempt") else {
        anyhow::bail!("J2 stored no MemberJoined");
    };
    anyhow::ensure!(
        matches!(
            &j2_joined,
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(_),
                ..
            }
        ),
        "J2's MemberJoined carries its KeyPackage"
    );
    for (joiner, joined) in [(&j1, j1_joined), (&j2, j2_joined)] {
        anyhow::ensure!(
            apply_named_group_metadata_event(
                &authority,
                joined,
                joiner.agent.agent_id(),
                true,
                None
            )
            .await
            .accepted,
            "the authority seals the add through its real MemberJoined apply"
        );
    }
    let j1_add = staged(&authority, &stable, &hex_of(&j1))
        .await
        .map(|p| p.event)
        .ok_or_else(|| anyhow::anyhow!("J1 result staged"))?;
    let j2_add = staged(&authority, &stable, &hex_of(&j2))
        .await
        .map(|p| p.event)
        .ok_or_else(|| anyhow::anyhow!("J2 result staged"))?;
    anyhow::ensure!(revision_of(&j1_add) == Some(base + 1), "J1 sealed at r+1");
    anyhow::ensure!(revision_of(&j2_add) == Some(base + 2), "J2 sealed at r+2");
    anyhow::ensure!(
        welcome_id_of(&j2_add).is_some(),
        "J2's Welcome is staged by reference"
    );
    Ok(Fixture {
        dir: dir.to_path_buf(),
        authority_id: authority.agent.agent_id(),
        authority,
        group_key,
        stable,
        base,
        j1,
        j2,
        j2_kp: j2_bytes,
        j1_attempt,
        j2_attempt,
        j1_add,
        j2_add,
    })
}

/// Shape A: only the ADR 0106 carry (J1's r+1) reaches J2, then its attempt
/// times out — a durable `not_member` remnant at r+1 with no own seat.
async fn stuck_with_carry(s: &Fixture) -> anyhow::Result<()> {
    super::super::apply_join_result_intervening_events(
        &s.j2,
        &s.authority_id,
        true,
        &s.stable,
        Some(s.base + 2),
        Some(s.j2_attempt.as_str()),
        vec![s.j1_add.clone()],
    )
    .await;
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable,
        &hex_of(&s.j2),
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    anyhow::ensure!(
        local_state(&s.j2, &s.group_key).await == "not_member",
        "stuck precondition: durable not_member remnant"
    );
    anyhow::ensure!(
        remnant_revision(&s.j2, &s.group_key).await == Some(s.base + 1),
        "the carry left the remnant at r+1"
    );
    Ok(())
}

async fn remnant_revision(joiner: &AppState, group_key: &str) -> Option<u64> {
    joiner
        .named_groups
        .read()
        .await
        .get(group_key)
        .map(|i| i.state_revision)
}

/// The re-arm contract on J2's row: the pre-seat prefix is unchanged.
async fn assert_pre_seat_prefix_kept(s: &Fixture, joiner: &AppState, ctx: &str) {
    let row = joiner
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("the remnant row is kept");
    let j1_hash = named_group_metadata_event_commit(&s.j1_add)
        .map(|c| c.state_hash.clone())
        .expect("J1 commit");
    assert_eq!(
        row.state_revision,
        s.base + 1,
        "[{ctx}] re-arm keeps the pre-seat revision (no base-seat shortcut)"
    );
    assert_eq!(
        row.state_hash, j1_hash,
        "[{ctx}] re-arm keeps the verified chain prefix"
    );
    assert!(
        row.invite_lineage
            .as_ref()
            .is_some_and(|l| l.seated_at_revision.is_none()),
        "[{ctx}] the lineage is not marked seated from the invite base"
    );
    assert!(
        !row.members_v2.contains_key(&hex_of(joiner)),
        "[{ctx}] the invite base's seat for this device was not installed"
    );
}

async fn seed_leftover_treekem(joiner: &AppState, group_key: &str) -> anyhow::Result<()> {
    let group_bytes = hex::decode(group_key)?;
    let seed = agent_treekem_seed(&joiner.agent, &group_bytes);
    let leftover = x0x::mls::TreeKemMlsGroup::create(group_bytes, joiner.agent.agent_id(), &seed)?;
    joiner.treekem_groups.write().await.insert(
        group_key.to_string(),
        Arc::new(tokio::sync::Mutex::new(leftover)),
    );
    Ok(())
}

/// Redeem a fresh base-seated invite from the original sealer, then return
/// the new attempt (if one was registered) with the route's body.
async fn redeem_fresh_invite(
    s: &Fixture,
    joiner: &Arc<AppState>,
    minted_by: &AppState,
) -> anyhow::Result<(StatusCode, serde_json::Value, Option<String>)> {
    let link = mint_for(minted_by, &s.group_key, joiner).await?;
    redeem_link(s, joiner, link).await
}

async fn redeem_link(
    s: &Fixture,
    joiner: &Arc<AppState>,
    link: String,
) -> anyhow::Result<(StatusCode, serde_json::Value, Option<String>)> {
    let before = attempt_of(joiner, &s.stable).map(|(id, _)| id);
    let (status, body) = join(joiner, link, Some(owner_pin_of(&s.authority))).await?;
    let after = attempt_of(joiner, &s.stable)
        .map(|(id, _)| id)
        .filter(|id| Some(id) != before.as_ref());
    Ok((status, body, after))
}

/// WHY (ADR 0107 Validation, Shape A red/green): the #1150 mechanism. The
/// authority sealed J2's add and still holds the ORIGINAL staged result and
/// Welcome; J2 kept only the carry. A fresh base-seated invite from the
/// original sealer must re-arm the remnant (new bound attempt, pre-seat
/// prefix kept, clear and base-seat shortcut both skipped, leftover TreeKEM
/// entry dropped) so the authority's original artifacts apply gaplessly and
/// the Welcome installs. Red before S8 (a): the base-seat shortcut reports
/// `active` from the snapshot and the original r+2 add is then stale, so the
/// device stays keyless.
#[tokio::test]
async fn s8a_1150_carry_remnant_rearms_and_installs_the_original_welcome() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let j2_hex = hex_of(&s.j2);
    let original = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .expect("the original result is still staged");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(s
        .authority
        .pending_welcomes
        .read()
        .await
        .contains_key(&welcome_id));
    let authority_revision = remnant_revision(&s.authority, &s.group_key).await;
    seed_leftover_treekem(&s.j2, &s.group_key).await?;

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "a base-seated fresh invite re-arms the carry remnant instead of reporting the \
         snapshot seat: {body}"
    );
    let new_attempt = new_attempt.expect("re-arm registered a NEW bound attempt");
    assert_ne!(new_attempt, s.j2_attempt);
    assert_pre_seat_prefix_kept(&s, &s.j2, "after re-arm").await;
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "re-arm drops the leftover TreeKEM entry: it must not satisfy the poll"
    );
    assert_ne!(local_state(&s.j2, &s.group_key).await, "active");

    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the authority serves the still-staged ORIGINAL result");
    let JoinResultMessage::Result { event, .. } = &served else {
        panic!("a Result is served");
    };
    assert_eq!(
        revision_of(event),
        Some(s.base + 2),
        "the original add, not a new one"
    );
    assert!(
        serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
        "the authority streams the original Welcome"
    );
    let served = with_inline_welcome(&s.authority, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(
        keyed(&s.j2, &s.group_key).await,
        "the recovered Welcome installed usable TreeKEM keys"
    );
    assert_eq!(
        remnant_revision(&s.authority, &s.group_key).await,
        authority_revision,
        "recovery needed no new membership commit"
    );
    let after = staged(&s.authority, &s.stable, &j2_hex).await;
    assert!(
        after.is_none_or(|p| p.created_at == original.created_at),
        "a retry never restarts the staged result's lifetime"
    );
    Ok(())
}

/// WHY (ADR 0107 Validation, joiner restart): the TreeKEM identity is
/// re-derived from the agent secret (ADR 0012), so a RESTARTED joiner with the
/// same agent key re-arms its durable remnant and decrypts the ORIGINAL
/// Welcome — and nothing secret was written to disk to make that possible.
#[tokio::test]
async fn s8a_1150_rearm_recovers_after_joiner_restart_without_stored_secrets() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    // Restart J2: a new daemon over the same data dir and agent key.
    let restarted = device(&s.dir, "j2", keypair(&s.j2_kp)?).await?;
    assert_eq!(
        local_state(&restarted, &s.group_key).await,
        "not_member",
        "the durable carry remnant survives the restart"
    );
    // The TreeKEM identity is re-derived from the agent secret and group id
    // (a re-prepared KeyPackage carries a fresh signature, so only the
    // Welcome decryption below proves the identity matches). No serialized
    // PreparedMember secret: the derivation seed appears in no file the
    // joiner wrote.
    let group_bytes = hex::decode(&s.group_key)?;
    let seed = agent_treekem_seed(&restarted.agent, &group_bytes);
    let needles = [
        seed.to_vec(),
        hex::encode(seed).into_bytes(),
        BASE64.encode(seed).into_bytes(),
    ];
    let mut stack = vec![s.dir.join("j2")];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            for needle in &needles {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "{} holds TreeKEM secret material",
                    entry.path().display()
                );
            }
        }
    }

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &restarted, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "the restarted joiner re-arms: {body}"
    );
    let new_attempt = new_attempt.expect("re-arm registered a new attempt");
    assert_pre_seat_prefix_kept(&s, &restarted, "restarted").await;
    let served = serve_result(
        &s.authority,
        &restarted,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the original result is served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &restarted, &s.stable, &welcome_id).await);
    let served = with_inline_welcome(&s.authority, served).await;
    deliver(&restarted, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&restarted, &s.group_key).await, "active");
    assert!(
        keyed(&restarted, &s.group_key).await,
        "the original Welcome decrypted under the re-derived identity"
    );
    Ok(())
}

/// WHY (ADR 0107 bounds): the re-armed attempt is bound — a result delivered
/// for the OLD attempt or by a device other than the invite's inviter applies
/// nothing — and the re-arm sends no `MemberJoined` volley (the authority's
/// step 7 would only reject it as an Active replay).
#[tokio::test]
async fn s8a_1150_rearm_rejects_stale_attempts_and_sends_no_volley() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    s.j2.named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish witness")
        .clear();
    s.j2.named_group_test_recorders
        .direct_deliveries
        .lock()
        .expect("delivery witness")
        .clear();

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "re-armed: {body}"
    );
    let new_attempt = new_attempt.expect("new attempt");
    let published_member_joined =
        s.j2.named_group_test_recorders
            .publish_bytes
            .lock()
            .expect("publish witness")
            .iter()
            .filter_map(|(_, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
            .any(|e| matches!(e, NamedGroupMetadataEvent::MemberJoined { .. }));
    let delivered_member_joined =
        s.j2.named_group_test_recorders
            .direct_deliveries
            .lock()
            .expect("delivery witness")
            .iter()
            .any(|(_, _, kind, _)| *kind == "member_joined");
    assert!(
        !published_member_joined && !delivered_member_joined,
        "the re-arm suppresses the redundant MemberJoined volley"
    );

    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_inline_welcome(&s.authority, served).await;
    // The OLD (finalized) attempt is stale: nothing applies.
    deliver(&s.j2, &s.authority_id, served.clone(), &s.j2_attempt).await;
    assert!(!keyed(&s.j2, &s.group_key).await, "stale attempt applied");
    // A copy from a device that is not the invite's inviter is ignored.
    deliver(&s.j2, &s.j1.agent.agent_id(), served.clone(), &new_attempt).await;
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "a result from a non-inviter applied"
    );
    assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
    // The current attempt from the original sealer converges.
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert!(keyed(&s.j2, &s.group_key).await);
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    Ok(())
}

/// WHY (ADR 0107 Validation, "disabling re-arm reproduces the keyless
/// failure"): with the re-arm switched off, the same fixture takes the
/// pre-S8 (a) path — the remnant is cleared, the base-seat shortcut reports
/// the snapshot seat, and the authority's ORIGINAL add is stale at the base
/// revision, so its Welcome is never consumed and the device stays keyless
/// (#1150).
#[tokio::test]
async fn s8a_1150_disabling_rearm_reproduces_the_keyless_failure() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let _disabled = super::super::disable_rearm_for_test(&s.group_key);
    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "active",
        "without re-arm the base-seat shortcut reports the snapshot seat: {body}"
    );
    let new_attempt = new_attempt.expect("the ordinary path registered an attempt");
    let from = remnant_revision(&s.j2, &s.group_key).await;
    assert_eq!(from, Some(s.base + 2), "the row jumped to the invite base");
    let served = serve_result(&s.authority, &s.j2, &s.stable, &new_attempt, from)
        .await
        .expect("the eligible device is still served its original result");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_inline_welcome(&s.authority, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "#1150: the original add is stale at the base revision; the device stays keyless"
    );
    Ok(())
}

/// WHY (ADR 0107 bounds): re-arm restores the ORIGINAL seat only. A commit
/// the authority sealed after J2's add (a third device at r+3) is not part of
/// the recovered result: J2 ends keyed at r+2 and still needs ordinary
/// catch-up (#818) to reach the authority's head.
#[tokio::test]
async fn s8a_1150_rearm_restores_the_original_seat_and_post_seal_commits_need_catch_up(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let j3 = device(&s.dir, "j3", x0x::identity::AgentKeypair::generate()?).await?;
    let link = mint_for(&s.authority, &s.group_key, &j3).await?;
    let (status, body) = join(&j3, link, Some(owner_pin_of(&s.authority))).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, Some(j3_joined)) = attempt_of(&j3, &s.stable).expect("J3 attempt") else {
        panic!("J3 stored its MemberJoined");
    };
    assert!(
        apply_named_group_metadata_event(&s.authority, j3_joined, j3.agent.agent_id(), true, None)
            .await
            .accepted,
        "the authority seals a post-seal commit"
    );
    assert_eq!(
        remnant_revision(&s.authority, &s.group_key).await,
        Some(s.base + 3)
    );

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(join_state_of(&body), "pending_authority_commit", "{body}");
    let new_attempt = new_attempt.expect("re-arm attempt");
    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the original result is served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_inline_welcome(&s.authority, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(keyed(&s.j2, &s.group_key).await);
    assert_eq!(
        remnant_revision(&s.j2, &s.group_key).await,
        Some(s.base + 2),
        "restoring the Welcome alone does not reach the authority's r+3 head"
    );
    Ok(())
}

/// The operator exit after a failed re-arm (ADR 0107): owner remove-member,
/// then a fresh invite (whose base no longer seats the device) clears the
/// remnant and admits the device again through the ordinary join — served by
/// the guarded paths, ending keyed-active.
async fn owner_remove_and_reinvite_restores_keys(s: &Fixture, ctx: &str) -> anyhow::Result<()> {
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    anyhow::ensure!(
        removed.status().is_success(),
        "[{ctx}] owner remove-member: {}",
        removed.status()
    );
    let (status, body, attempt) = redeem_fresh_invite(s, &s.j2, &s.authority).await?;
    anyhow::ensure!(
        status == StatusCode::OK && join_state_of(&body) == "pending_authority_commit",
        "[{ctx}] re-invite: {status} {body}"
    );
    let attempt = attempt.ok_or_else(|| anyhow::anyhow!("[{ctx}] no new attempt"))?;
    let Some((_, Some(joined))) = attempt_of(&s.j2, &s.stable) else {
        anyhow::bail!("[{ctx}] the ordinary join stored its MemberJoined");
    };
    anyhow::ensure!(
        apply_named_group_metadata_event(&s.authority, joined, s.j2.agent.agent_id(), true, None)
            .await
            .accepted,
        "[{ctx}] the authority re-admits the removed device"
    );
    let staged_add = staged(&s.authority, &s.stable, &hex_of(&s.j2))
        .await
        .ok_or_else(|| anyhow::anyhow!("[{ctx}] re-admission staged"))?
        .event;
    let from = remnant_revision(&s.j2, &s.group_key).await;
    let served = serve_result(&s.authority, &s.j2, &s.stable, &attempt, from)
        .await
        .ok_or_else(|| anyhow::anyhow!("[{ctx}] the re-admitted device is served"))?;
    let welcome_id =
        welcome_id_of(&staged_add).ok_or_else(|| anyhow::anyhow!("[{ctx}] welcome ref"))?;
    anyhow::ensure!(
        serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
        "[{ctx}] the re-admission Welcome is streamed"
    );
    let served = with_inline_welcome(&s.authority, served).await;
    deliver(&s.j2, &s.authority_id, served, &attempt).await;
    anyhow::ensure!(
        local_state(&s.j2, &s.group_key).await == "active" && keyed(&s.j2, &s.group_key).await,
        "[{ctx}] owner remove-member + re-invite restores membership WITH keys"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LostStaging {
    ResultExpired,
    WelcomeExpired,
    AuthorityRestarted,
}

/// WHY (ADR 0107 bounds): the re-arm depends on the original sealer's
/// in-memory caches. An expired result, an expired Welcome or an authority
/// restart loses the route: the joiner must never claim recovery or
/// confirmation, and the attempt ends with the typed `timed_out` outcome.
#[tokio::test]
async fn s8a_1150_lost_staging_never_claims_recovery() -> anyhow::Result<()> {
    for case in [
        LostStaging::ResultExpired,
        LostStaging::WelcomeExpired,
        LostStaging::AuthorityRestarted,
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        stuck_with_carry(&s).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        let expired = Instant::now()
            .checked_sub(super::super::PENDING_JOIN_RESULT_TTL + Duration::from_secs(1))
            .expect("monotonic clock far enough from boot");
        let serving = match case {
            LostStaging::ResultExpired => {
                if let Some(p) = s
                    .authority
                    .pending_join_results
                    .write()
                    .await
                    .get_mut(&join_result_key(&s.stable, &j2_hex))
                {
                    p.created_at = expired;
                }
                Arc::clone(&s.authority)
            }
            LostStaging::WelcomeExpired => {
                if let Some(w) = s
                    .authority
                    .pending_welcomes
                    .write()
                    .await
                    .get_mut(&welcome_id)
                {
                    w.created_at = expired;
                }
                Arc::clone(&s.authority)
            }
            LostStaging::AuthorityRestarted => {
                super::super::super::home::tests::owned_state(&s.dir, OWNER_SEED).await?
            }
        };
        let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &serving).await?;
        assert_eq!(status, StatusCode::OK, "[{case:?}] {body}");
        assert_ne!(
            join_state_of(&body),
            "active",
            "[{case:?}] a base-seated invite must not claim confirmed membership: {body}"
        );
        let new_attempt = new_attempt.expect("re-arm registered an attempt");
        let served = serve_result(&serving, &s.j2, &s.stable, &new_attempt, Some(s.base + 1)).await;
        match case {
            // Without the result the device never learns the Welcome
            // reference, so it has nothing to pull.
            LostStaging::ResultExpired => {
                assert!(served.is_none(), "[{case:?}] no result to serve");
            }
            LostStaging::WelcomeExpired => {
                assert!(served.is_some(), "[{case:?}] the result is still staged");
                assert!(
                    !serve_welcome(&serving, &s.j2, &s.stable, &welcome_id).await,
                    "[{case:?}] no Welcome to stream"
                );
            }
            LostStaging::AuthorityRestarted => {
                assert!(served.is_none(), "[{case:?}] no result to serve");
                assert!(
                    !serve_welcome(&serving, &s.j2, &s.stable, &welcome_id).await,
                    "[{case:?}] no Welcome to stream"
                );
            }
        }
        assert!(!keyed(&s.j2, &s.group_key).await, "[{case:?}] keyed");
        assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
        super::super::finalize_join_attempt(
            &s.j2,
            &s.group_key,
            &s.stable,
            &j2_hex,
            &new_attempt,
            super::super::JoinAttemptOutcome::TimedOut,
            super::super::JoinFinalizeGuard::Unlocked,
        )
        .await;
        assert_rearm_timed_out(&s.j2, &s.group_key, &format!("{case:?}"));
        assert_eq!(
            local_state(&s.j2, &s.group_key).await,
            "not_member",
            "[{case:?}] a failed re-arm leaves the remnant for owner remove-member + re-invite"
        );
        // The eligible-device exit works from that state (an authority that
        // restarted reloads no TreeKEM group in this fixture, so its exit is
        // the same route and is not repeated here).
        if !matches!(case, LostStaging::AuthorityRestarted) {
            owner_remove_and_reinvite_restores_keys(&s, &format!("{case:?}")).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PostSeal {
    Banned,
    Removed,
    CertificateRevoked,
}

async fn revoke_agent(authority: &AppState, kp: &(Vec<u8>, Vec<u8>)) -> anyhow::Result<()> {
    let kp = keypair(kp)?;
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(kp.agent_id()),
        kp.public_key(),
        kp.secret_key(),
        x0x::groups::owner_cert::restore_clock_now(),
        Some("adr0107 revocation".to_string()),
    )?;
    authority
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)?;
    Ok(())
}

async fn apply_post_seal(s: &Fixture, case: PostSeal) -> anyhow::Result<()> {
    let j2_hex = hex_of(&s.j2);
    match case {
        PostSeal::Banned => {
            s.authority
                .named_groups
                .write()
                .await
                .get_mut(&s.group_key)
                .expect("authority group")
                .ban_member(&j2_hex, None);
        }
        PostSeal::Removed => {
            s.authority
                .named_groups
                .write()
                .await
                .get_mut(&s.group_key)
                .expect("authority group")
                .remove_member(&j2_hex, None);
        }
        PostSeal::CertificateRevoked => revoke_agent(&s.authority, &s.j2_kp).await?,
    }
    Ok(())
}

/// WHY (ADR 0107 Validation, #1149 + carry, must not gain keys): the
/// authority mints a base-seated invite, THEN bans, removes or revokes J2
/// while its ORIGINAL result and Welcome stay staged. J2 redeems the old
/// invite: the re-arm must not report the snapshot seat, neither serving path
/// may hand the ineligible device anything, and J2 must never end
/// keyed-active (typed `timed_out`, row back to `not_member`). Red before
/// S8 (a): J2 reports `active` from the snapshot alone.
#[tokio::test]
async fn s8a_1149_carry_remnant_never_gains_keys_after_post_seal_ineligibility(
) -> anyhow::Result<()> {
    for case in [
        PostSeal::Banned,
        PostSeal::Removed,
        PostSeal::CertificateRevoked,
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        stuck_with_carry(&s).await?;
        let link = mint_for(&s.authority, &s.group_key, &s.j2).await?;
        apply_post_seal(&s, case).await?;
        assert!(
            staged(&s.authority, &s.stable, &hex_of(&s.j2))
                .await
                .is_some(),
            "[{case:?}] original caches intact"
        );
        let (status, body, new_attempt) = redeem_link(&s, &s.j2, link).await?;
        assert_eq!(status, StatusCode::OK, "[{case:?}] {body}");
        assert_ne!(
            join_state_of(&body),
            "active",
            "[{case:?}] a stale base-seated invite is not current admission: {body}"
        );
        assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
        let new_attempt = new_attempt.expect("re-arm registered an attempt");
        assert!(
            serve_result(
                &s.authority,
                &s.j2,
                &s.stable,
                &new_attempt,
                Some(s.base + 1)
            )
            .await
            .is_none(),
            "[{case:?}] no join result may be served to an ineligible member"
        );
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        assert!(
            !serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
            "[{case:?}] no Welcome may be streamed to an ineligible member"
        );
        super::super::finalize_join_attempt(
            &s.j2,
            &s.group_key,
            &s.stable,
            &hex_of(&s.j2),
            &new_attempt,
            super::super::JoinAttemptOutcome::TimedOut,
            super::super::JoinFinalizeGuard::Unlocked,
        )
        .await;
        assert_rearm_timed_out(&s.j2, &s.group_key, &format!("{case:?}"));
        assert_eq!(local_state(&s.j2, &s.group_key).await, "not_member");
        assert!(
            !keyed(&s.j2, &s.group_key).await,
            "[{case:?}] never keyed-active"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Ineligible {
    Banned,
    Removed,
    Expired,
    ForeignOwner,
    DigestPending,
    InGrace,
    Revoked,
}

/// Insert a VALID owner certificate for `agent` into the authority's
/// announce/discovery cache — which the serving guard must NOT consult.
async fn announce_valid_cert(authority: &AppState, cert: x0x::identity::AgentCertificate) {
    let agent_id = cert.agent_id().expect("cert agent id");
    authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(
            agent_id,
            x0x::DiscoveredAgent {
                agent_id,
                machine_id: x0x::identity::MachineId([0u8; 32]),
                user_id: cert.user_id().ok(),
                self_name: None,
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: cert.not_after(),
                agent_certificate: Some(cert),
                agent_public_key: Vec::new(),
                cert_digest: None,
            },
        );
}

/// WHY (ADR 0107 serving guard): both serving paths serve a requester only
/// while it is Active, not banned and certificate-valid on the CURRENT
/// committed roster. The roster is mutated directly here (no route, so no
/// purge runs): the guard alone must refuse. OwnerCertified serving uses the
/// ROSTER-EMBEDDED certificate with the current revocation set and clock — a
/// valid certificate in the announce/discovery cache never rescues an
/// expired or foreign one — and DigestPending/InGrace fail closed. The
/// control (an eligible, inline-certified first join with no announce) is
/// served on both paths.
#[tokio::test]
async fn s8a_serving_guard_refuses_ineligible_requesters_on_both_paths() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let roster = s
        .authority
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("authority group");
    let result = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .expect("staged");
    let welcome = s
        .authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .cloned()
        .expect("staged Welcome");
    assert!(
        roster
            .members_v2
            .get(&j2_hex)
            .is_some_and(|m| m.certificate.is_some()),
        "the seal embedded J2's inline (#842) certificate in the roster"
    );
    assert!(
        s.authority
            .agent
            .identity_discovery_cache()
            .read()
            .await
            .get(&s.j2.agent.agent_id())
            .is_none_or(|d| d.agent_certificate.is_none()),
        "no announce for J2 reached the authority"
    );

    let restore = || async {
        s.authority
            .named_groups
            .write()
            .await
            .insert(s.group_key.clone(), roster.clone());
        s.authority
            .pending_join_results
            .write()
            .await
            .insert(join_result_key(&s.stable, &j2_hex), result.clone());
        s.authority
            .pending_welcomes
            .write()
            .await
            .insert(welcome_id.clone(), welcome.clone());
        s.authority
            .agent
            .identity_discovery_cache()
            .write()
            .await
            .remove(&s.j2.agent.agent_id());
    };
    let served = |ctx: String| {
        let s = &s;
        let welcome_id = welcome_id.clone();
        async move {
            let result = serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
                .await
                .is_some();
            let welcome = serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await;
            (ctx, result, welcome)
        }
    };

    let (ctx, result_served, welcome_served) = served("eligible control".into()).await;
    assert!(
        result_served && welcome_served,
        "[{ctx}] an eligible first join is served on both paths"
    );

    let mut leaks = Vec::new();
    for case in [
        Ineligible::Banned,
        Ineligible::Removed,
        Ineligible::Expired,
        Ineligible::ForeignOwner,
        Ineligible::DigestPending,
        Ineligible::InGrace,
        Ineligible::Revoked,
    ] {
        restore().await;
        let (ctx, result_served, welcome_served) = served(format!("{case:?} control")).await;
        assert!(result_served && welcome_served, "[{ctx}] restored");
        {
            let j2_kp = keypair(&s.j2_kp)?;
            let mut groups = s.authority.named_groups.write().await;
            let info = groups.get_mut(&s.group_key).expect("authority group");
            match case {
                Ineligible::Banned => {
                    info.ban_member(&j2_hex, None);
                }
                Ineligible::Removed => {
                    info.remove_member(&j2_hex, None);
                }
                Ineligible::Expired => {
                    let past = x0x::groups::owner_cert::restore_clock_now() - 30 * 86_400;
                    let expired = x0x::identity::AgentCertificate::issue_with_expiry(
                        &owner_kp,
                        &j2_kp,
                        Some(past),
                    )?;
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = Some(expired);
                    }
                }
                Ineligible::ForeignOwner => {
                    let stranger = x0x::identity::UserKeypair::generate()?;
                    let foreign = x0x::identity::AgentCertificate::issue(&stranger, &j2_kp)?;
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = Some(foreign);
                    }
                }
                Ineligible::DigestPending => {
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = None;
                    }
                }
                Ineligible::InGrace => {
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = None;
                        m.certificate_digest = None;
                    }
                }
                Ineligible::Revoked => {}
            }
            let status = info
                .clone()
                .owner_cert_verdict(&x0x::groups::owner_cert::OwnerCertEvidence::new(
                    x0x::groups::owner_cert::restore_clock_now(),
                ))
                .per_member
                .get(&j2_hex)
                .cloned();
            match case {
                Ineligible::DigestPending => assert_eq!(
                    status,
                    Some(x0x::groups::owner_cert::MemberCertStatus::DigestPending)
                ),
                Ineligible::InGrace => assert!(
                    matches!(
                        status,
                        Some(x0x::groups::owner_cert::MemberCertStatus::InGrace { .. })
                    ),
                    "fixture shape is InGrace: {status:?}"
                ),
                _ => {}
            }
        }
        match case {
            Ineligible::Expired | Ineligible::ForeignOwner => {
                announce_valid_cert(
                    &s.authority,
                    x0x::identity::AgentCertificate::issue(&owner_kp, &keypair(&s.j2_kp)?)?,
                )
                .await;
            }
            Ineligible::Revoked => revoke_agent(&s.authority, &s.j2_kp).await?,
            _ => {}
        }
        let (ctx, result_served, welcome_served) = served(format!("{case:?}")).await;
        if result_served {
            leaks.push(format!("{ctx}: FetchRequest arm served a join result"));
        }
        if welcome_served {
            leaks.push(format!("{ctx}: Welcome path streamed key material"));
        }
    }
    assert!(
        leaks.is_empty(),
        "ineligible requesters were served: {leaks:#?}"
    );
    Ok(())
}

/// WHY (ADR 0107 purge): an owner removal or ban through the production
/// routes drops that member's staged join result and Welcome and cancels its
/// unsent Welcome transfer, so a previously copied cache entry cannot bypass
/// the guard. The streams are parked at the test gate (registered, not yet
/// sent) when the mutation lands.
#[tokio::test]
async fn s8a_owner_remove_and_ban_purge_staged_artifacts_and_cancel_transfers() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let gates = super::super::WELCOME_STREAM_TEST_GATES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut parked = Vec::new();
    for (joiner, add) in [(&s.j1, &s.j1_add), (&s.j2, &s.j2_add)] {
        let welcome_id = welcome_id_of(add).expect("welcome ref");
        gates
            .lock()
            .map_err(|_| anyhow::anyhow!("gate map"))?
            .insert(welcome_id.clone(), Arc::new(tokio::sync::Notify::new()));
        assert!(serve_welcome(&s.authority, joiner, &s.stable, &welcome_id).await);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !s
                .authority
                .pending_welcome_acks
                .read()
                .await
                .contains_key(&welcome_id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        parked.push((Arc::clone(joiner), welcome_id));
    }

    let owner =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        owner.clone(),
        Path((s.group_key.clone(), hex_of(&s.j1))),
    )
    .await
    .into_response();
    assert!(
        removed.status().is_success(),
        "remove: {}",
        removed.status()
    );
    let banned = ban_group_member(
        State(Arc::clone(&s.authority)),
        owner,
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    assert!(banned.status().is_success(), "ban: {}", banned.status());

    for (joiner, welcome_id) in &parked {
        let who = if Arc::ptr_eq(joiner, &s.j1) {
            "removed J1"
        } else {
            "banned J2"
        };
        assert!(
            staged(&s.authority, &s.stable, &hex_of(joiner))
                .await
                .is_none(),
            "[{who}] the staged join result is dropped"
        );
        assert!(
            !s.authority
                .pending_welcomes
                .read()
                .await
                .contains_key(welcome_id),
            "[{who}] the staged Welcome is dropped"
        );
        assert!(
            !s.authority
                .pending_welcome_streams
                .lock()
                .await
                .as_ref()
                .is_some_and(|streams| streams.contains_key(welcome_id)),
            "[{who}] the unsent Welcome transfer is cancelled"
        );
        assert!(
            !s.authority
                .pending_welcome_acks
                .read()
                .await
                .contains_key(welcome_id),
            "[{who}] the transfer's ack slot is released"
        );
        if let Ok(mut gates) = gates.lock() {
            gates.remove(welcome_id);
        }
    }
    Ok(())
}

/// WHY (ADR 0107 serving non-regression, TreeKEM): ordinary eligible first
/// joins — certified INLINE (#842) with no announce at the authority — still
/// receive their staged results and Welcomes, and the #1139 / ADR 0106
/// intervening-events carry is still served and applied before the joiner's
/// own event.
#[tokio::test]
async fn s8a_serving_non_regression_treekem_first_joins_and_adr0106_carry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    for (joiner, attempt, add, carried) in [
        (&s.j1, &s.j1_attempt, &s.j1_add, Vec::<u64>::new()),
        (&s.j2, &s.j2_attempt, &s.j2_add, vec![s.base + 1]),
    ] {
        assert!(
            s.authority
                .agent
                .identity_discovery_cache()
                .read()
                .await
                .get(&joiner.agent.agent_id())
                .is_none_or(|d| d.agent_certificate.is_none()),
            "announce absent"
        );
        let served = serve_result(&s.authority, joiner, &s.stable, attempt, Some(s.base))
            .await
            .expect("an eligible first join is served");
        let JoinResultMessage::Result {
            event,
            intervening_events,
            ..
        } = &served
        else {
            panic!("a Result is served");
        };
        assert_eq!(revision_of(event), revision_of(add));
        assert_eq!(
            intervening_events
                .iter()
                .filter_map(revision_of)
                .collect::<Vec<_>>(),
            carried,
            "the ADR 0106 carry is unchanged"
        );
        let welcome_id = welcome_id_of(add).expect("welcome ref");
        assert!(serve_welcome(&s.authority, joiner, &s.stable, &welcome_id).await);
        let served = with_inline_welcome(&s.authority, served).await;
        deliver(joiner, &s.authority_id, served, attempt).await;
        assert_eq!(local_state(joiner, &s.group_key).await, "active");
        assert!(keyed(joiner, &s.group_key).await);
    }
    Ok(())
}

/// WHY (ADR 0107 serving non-regression, GSS): GSS-plane first joins are
/// served too — an OwnerCertified group whose joiner is certified inline with
/// no announce, and an ordinary invite-only group that needs no certificate.
#[tokio::test]
async fn s8a_serving_non_regression_gss_first_joins() -> anyhow::Result<()> {
    for owner_certified in [true, false] {
        let dir = tempfile::tempdir()?;
        let authority =
            super::super::super::home::tests::owned_state(dir.path(), OWNER_SEED).await?;
        let owner = owner_pin_of(&authority);
        let owner_id = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?.user_id();
        let policy = x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::ListedToContacts,
            admission: if owner_certified {
                x0x::groups::GroupAdmission::OwnerCertified(owner_id)
            } else {
                x0x::groups::GroupAdmission::InviteOnly
            },
            confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        };
        let created = create_named_group(
            State(Arc::clone(&authority)),
            Json(CreateGroupRequest {
                name: "gss".to_string(),
                description: String::new(),
                display_name: None,
                preset: None,
                policy: Some(policy),
            }),
        )
        .await
        .into_response();
        let status = created.status();
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(created.into_body(), usize::MAX).await?)?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let group_key = body["group_id"].as_str().unwrap_or_default().to_string();
        let stable = {
            let groups = authority.named_groups.read().await;
            let info = groups.get(&group_key).expect("created group");
            assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::Gss);
            info.stable_group_id().to_string()
        };
        let joiner = device(dir.path(), "g", x0x::identity::AgentKeypair::generate()?).await?;
        let link = mint_for(&authority, &group_key, &joiner).await?;
        let (status, body) = join(&joiner, link, owner_certified.then(|| owner.clone())).await?;
        assert_eq!(status, StatusCode::OK, "[oc={owner_certified}] {body}");
        let (attempt, Some(joined)) = attempt_of(&joiner, &stable).expect("attempt") else {
            panic!("stored MemberJoined");
        };
        assert!(
            apply_named_group_metadata_event(
                &authority,
                joined,
                joiner.agent.agent_id(),
                true,
                None
            )
            .await
            .accepted,
            "[oc={owner_certified}] the authority seals the GSS add"
        );
        let from = remnant_revision(&joiner, &group_key).await;
        let served = serve_result(&authority, &joiner, &stable, &attempt, from)
            .await
            .unwrap_or_else(|| {
                panic!("[oc={owner_certified}] an eligible GSS first join is served")
            });
        deliver(&joiner, &authority.agent.agent_id(), served, &attempt).await;
        assert_eq!(
            local_state(&joiner, &group_key).await,
            "active",
            "[oc={owner_certified}] the served result seats the joiner"
        );
    }
    Ok(())
}
