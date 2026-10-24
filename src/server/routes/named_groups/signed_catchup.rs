//! Signed catch-up for a member whose transport is not verified (survivor
//! re-key A5, `docs/adr/transient/T-signed-catchup-pages.md`).
//!
//! A phone's engine, or an agent at rest, is often missing from its peers'
//! discovery caches, so its direct messages arrive with `verified == false`.
//! Before this, a member dropped its page requests, and it dropped every
//! page such a member was sent. Now:
//!
//! - **A page request carries its requester's signature** over
//!   ([`PAGE_REQUEST_DOMAIN`], group, requester, `from_revision`,
//!   `from_epoch`, `limit`, `head_challenge`). The key is self-certifying against the
//!   requester's agent id. A responder serves a signed request it could not
//!   verify, and every membership gate still applies.
//! - **On a page whose transport is not verified, the claimed sender counts
//!   for nothing.** It is not checked against the roster and nothing applies
//!   as it. Each event applies as its verified commit signer, a copy with
//!   TreeKEM bytes must name them in its signed binding and pass the
//!   committer-leaf rule, and anything else is dropped.

use super::{
    build_catchup_signer, catchup_signer_matches, named_group_direct_delivery_config, AppState,
    NamedGroupMetadataEvent, TreeKemCatchupRequest, TreeKemCatchupResponse,
    TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
};
use crate::identity::AgentId;

/// The domain of a page request's signature.
pub(super) const PAGE_REQUEST_DOMAIN: &str = "x0x/treekem-catchup-page/v1";

/// The domain of a responder's signature on a hole report.
pub(super) const GAP_REPORT_DOMAIN: &str = "x0x/treekem-catchup-gap/v1";

/// The longest `head_challenge` a signed page request may carry.
pub(super) const HEAD_CHALLENGE_MAX_BYTES: usize = 128;

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes a page request's signature covers. Every field after the
/// domain is length-prefixed, so no two requests share an encoding.
/// `limit` is covered too: a replay cannot turn a request into one for an
/// empty page (A5 review I-1).
pub(super) fn page_request_sign_input(
    group_id: &str,
    requester: &str,
    from_revision: u64,
    from_epoch: u64,
    limit: usize,
    head_challenge: Option<&str>,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(PAGE_REQUEST_DOMAIN.len() + 256);
    push_field(&mut input, PAGE_REQUEST_DOMAIN.as_bytes());
    push_field(&mut input, group_id.as_bytes());
    push_field(&mut input, requester.as_bytes());
    input.extend_from_slice(&from_revision.to_be_bytes());
    input.extend_from_slice(&from_epoch.to_be_bytes());
    input.extend_from_slice(&(limit as u64).to_be_bytes());
    match head_challenge {
        None => input.push(0),
        Some(challenge) => {
            input.push(1);
            push_field(&mut input, challenge.as_bytes());
        }
    }
    input
}

fn request_sign_input(request: &TreeKemCatchupRequest) -> Vec<u8> {
    page_request_sign_input(
        &request.group_id,
        &request.requester_agent_id,
        request.from_revision,
        request.from_treekem_epoch,
        request.limit,
        request.head_challenge.as_deref(),
    )
}

/// How many events a page served for `limit` holds: at least one, so no
/// request is answered with an empty page cut short, and at most the cap.
pub(super) fn page_limit(limit: usize) -> usize {
    limit.clamp(1, TREEKEM_CATCHUP_RESPONSE_EVENT_CAP)
}

/// The bytes a hole report's signature covers: the responder's log cannot
/// serve `requester` past `through` in `group_id`.
fn gap_report_sign_input(group_id: &str, requester: &str, through: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(GAP_REPORT_DOMAIN.len() + 160);
    push_field(&mut input, GAP_REPORT_DOMAIN.as_bytes());
    push_field(&mut input, group_id.as_bytes());
    push_field(&mut input, requester.as_bytes());
    input.extend_from_slice(&through.to_be_bytes());
    input
}

/// This daemon's signature on a hole report to `requester`, so a requester
/// that cannot verify the transport can tell it came from a member.
pub(super) fn sign_gap_report(
    state: &AppState,
    group_id: &str,
    requester: &str,
    through: u64,
) -> Option<super::CatchupSigner> {
    build_catchup_signer(state, &gap_report_sign_input(group_id, requester, through))
}

/// Whether `response` is a hole report to `requester` that `claimed_sender`
/// signed.
pub(super) fn gap_report_signed(
    response: &TreeKemCatchupResponse,
    claimed_sender: &str,
    requester: &str,
) -> bool {
    let (None, Some(through), Some(signer)) = (
        response.target_member_id.as_ref(),
        response.log_evicted_through,
        response.signed_by.as_ref(),
    ) else {
        return false;
    };
    catchup_signer_matches(
        signer,
        claimed_sender,
        &gap_report_sign_input(&response.group_id, requester, through),
    )
}

/// Sign `request` as this daemon's agent. A page request goes out signed
/// whatever the transport, since the requester cannot know whether the
/// responder will verify it. If signing fails it goes out unsigned, as
/// before.
pub(super) fn sign_page_request(state: &AppState, request: &mut TreeKemCatchupRequest) {
    request.signed_by = build_catchup_signer(state, &request_sign_input(request));
}

/// This member's signed page request for `group_key`, asking for what
/// comes after its head.
pub(super) async fn page_request(
    state: &AppState,
    group_key: &str,
    missing_prev_state_hash: Option<String>,
) -> Option<TreeKemCatchupRequest> {
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(group_key).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_key)
        })?;
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    let mut request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_key.to_string(),
        requester_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
        from_revision,
        from_treekem_epoch: from_epoch,
        current_state_hash,
        missing_prev_state_hash,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        signed_by: None,
        head_challenge: None,
    };
    sign_page_request(state, &mut request);
    Some(request)
}

/// Send a page request to `peer`, signed.
pub(super) async fn send_page_request(
    state: &AppState,
    peer: &AgentId,
    mut request: TreeKemCatchupRequest,
) -> Result<(), String> {
    if request.signed_by.is_none() {
        sign_page_request(state, &mut request);
    }
    let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if let Ok(mut recorded) = state
        .named_group_test_recorders
        .catchup_page_requests
        .lock()
    {
        recorded.push((hex::encode(peer.as_bytes()), payload.clone()));
    }
    state
        .agent
        .send_direct_with_config(peer, payload, named_group_direct_delivery_config())
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Sign `request` with `keypair`. A test plays a member that is not a
/// daemon (a removed member) with it.
#[cfg(test)]
pub(super) fn sign_page_request_with(
    keypair: &crate::identity::AgentKeypair,
    request: &mut TreeKemCatchupRequest,
) {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let input = request_sign_input(request);
    request.signed_by =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(keypair.secret_key(), &input)
            .ok()
            .map(|signature| super::CatchupSigner {
                public_key_b64: BASE64.encode(keypair.public_key().as_bytes()),
                signature_b64: BASE64.encode(signature.as_bytes()),
            });
}

/// Sign a hole report with `keypair`, as a test's stranger would.
#[cfg(test)]
pub(super) fn sign_gap_report_with(
    keypair: &crate::identity::AgentKeypair,
    group_id: &str,
    requester: &str,
    through: u64,
) -> Option<super::CatchupSigner> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let input = gap_report_sign_input(group_id, requester, through);
    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(keypair.secret_key(), &input)
        .ok()
        .map(|signature| super::CatchupSigner {
            public_key_b64: BASE64.encode(keypair.public_key().as_bytes()),
            signature_b64: BASE64.encode(signature.as_bytes()),
        })
}

/// Whether `request` is a page request (not a member-keyed one) that its
/// claimed requester signed, over exactly the fields it carries.
pub(super) fn page_request_signed(request: &TreeKemCatchupRequest) -> bool {
    if request.target_member_id.is_some()
        || request
            .head_challenge
            .as_ref()
            .is_some_and(|challenge| challenge.len() > HEAD_CHALLENGE_MAX_BYTES)
    {
        return false;
    }
    request.signed_by.as_ref().is_some_and(|signer| {
        catchup_signer_matches(
            signer,
            &request.requester_agent_id,
            &request_sign_input(request),
        )
    })
}

/// The events of a page whose transport is not verified that this member
/// looks at. An honest responder serves at most
/// [`TREEKEM_CATCHUP_RESPONSE_EVENT_CAP`] a page, and each event costs a
/// signature check, so a stranger cannot make it check more.
pub(super) fn unverified_page_events(
    mut events: Vec<NamedGroupMetadataEvent>,
) -> Vec<NamedGroupMetadataEvent> {
    events.truncate(TREEKEM_CATCHUP_RESPONSE_EVENT_CAP);
    events
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_sign_input_names_its_domain_and_every_field() {
        let base = page_request_sign_input("g", "r", 1, 2, 1, None);
        assert!(base
            .windows(PAGE_REQUEST_DOMAIN.len())
            .any(|window| window == PAGE_REQUEST_DOMAIN.as_bytes()));
        for other in [
            page_request_sign_input("h", "r", 1, 2, 1, None),
            page_request_sign_input("g", "s", 1, 2, 1, None),
            page_request_sign_input("g", "r", 9, 2, 1, None),
            page_request_sign_input("g", "r", 1, 9, 1, None),
            page_request_sign_input("g", "r", 1, 2, 0, None),
            page_request_sign_input("g", "r", 1, 2, 1, Some("")),
            page_request_sign_input("g", "r", 1, 2, 1, Some("n")),
        ] {
            assert_ne!(base, other);
        }
        // Moving bytes between fields changes the encoding.
        assert_ne!(
            page_request_sign_input("ab", "c", 1, 2, 1, None),
            page_request_sign_input("a", "bc", 1, 2, 1, None)
        );
    }

    #[test]
    fn a_page_holds_at_least_one_event_and_at_most_the_cap() {
        assert_eq!(page_limit(0), 1);
        assert_eq!(page_limit(1), 1);
        assert_eq!(page_limit(usize::MAX), TREEKEM_CATCHUP_RESPONSE_EVENT_CAP);
        assert_ne!(
            gap_report_sign_input("g", "r", 5),
            gap_report_sign_input("g", "r", 6)
        );
        assert_ne!(
            gap_report_sign_input("g", "r", 5),
            gap_report_sign_input("g", "s", 5)
        );
    }
}
