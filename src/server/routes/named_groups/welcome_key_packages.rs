//! A joiner seats its roster's KeyPackages from the Welcome it joins with
//! (survivor re-key A2, `docs/adr/transient/T-treekem-committer-leaf.md`).
//!
//! An invite seats existing members by their committed KeyPackage hash
//! only. The committer-leaf rule needs the actor's package bytes, so a
//! joiner would refuse each earlier member's first commit until a peer sent
//! the package. The Welcome's ratchet tree already holds every member's
//! package: one whose encoding hashes to a seat's committed hash is that
//! member's package, whoever delivered the Welcome.

use super::current_member_treekem_key_package;
use crate as x0x;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::HashMap;

/// Seat every hash-only member whose package the Welcome holds. Returns
/// the active members still held by hash alone, for the caller to request.
/// The roster root is unchanged: it commits the hash, which stays the same.
pub(super) fn seat_roster_key_packages_from_welcome(
    info: &mut x0x::groups::GroupInfo,
    welcome: &[u8],
) -> Vec<String> {
    let by_hash: HashMap<String, String> = x0x::mls::TreeKemMlsGroup::welcome_key_packages(welcome)
        .unwrap_or_default()
        .into_iter()
        .map(|bytes| {
            let b64 = BASE64.encode(bytes);
            (blake3::hash(b64.as_bytes()).to_hex().to_string(), b64)
        })
        .collect();
    let mut seat = Vec::new();
    let mut still_hash_only = Vec::new();
    for (member_hex, member) in &info.members_v2 {
        if current_member_treekem_key_package(member).is_some() {
            continue;
        }
        let Some(hash) = member.treekem_key_package_hash.as_deref() else {
            continue;
        };
        match by_hash.get(hash) {
            Some(b64) => seat.push((member_hex.clone(), b64.clone())),
            None if member.is_active() => still_hash_only.push(member_hex.clone()),
            None => {}
        }
    }
    for (member_hex, b64) in seat {
        info.set_member_treekem_key_package(&member_hex, b64);
    }
    still_hash_only
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::AgentId;
    use crate::mls::TreeKemMlsGroup;

    #[test]
    fn a_joiner_seats_the_packages_its_welcome_holds() {
        let creator = AgentId([1; 32]);
        let (admin, member, joiner) = (AgentId([2; 32]), AgentId([3; 32]), AgentId([4; 32]));
        let creator_prepared = TreeKemMlsGroup::prepare_member(creator, &[1; 32]).expect("p");
        let creator_kp = BASE64.encode(creator_prepared.key_package_bytes());
        let mut tree =
            TreeKemMlsGroup::create_prepared(b"seat".to_vec(), creator_prepared).expect("create");
        let mut info = x0x::groups::GroupInfo::new(
            "seat".to_string(),
            String::new(),
            creator,
            hex::encode([0x5a; 16]),
        );
        info.set_member_treekem_key_package(&hex::encode(creator.as_bytes()), creator_kp.clone());
        let mut packages = vec![(creator, creator_kp)];
        for (id, seed) in [(admin, [2; 32]), (member, [3; 32])] {
            let kp = TreeKemMlsGroup::prepare_member(id, &seed).expect("p");
            tree.add_member(id, kp.key_package_bytes()).expect("add");
            let b64 = BASE64.encode(kp.key_package_bytes());
            let hex_id = hex::encode(id.as_bytes());
            info.add_member(hex_id.clone(), x0x::groups::GroupRole::Admin, None, None);
            info.set_member_treekem_key_package(&hex_id, b64.clone());
            packages.push((id, b64));
        }
        let joiner_kp = TreeKemMlsGroup::prepare_member(joiner, &[4; 32]).expect("p");
        let welcome = tree
            .add_member(joiner, joiner_kp.key_package_bytes())
            .expect("add joiner")
            .welcome;

        // A stranger whose committed hash no leaf in the tree matches.
        let stranger = hex::encode([9; 32]);
        info.add_member(stranger.clone(), x0x::groups::GroupRole::Member, None, None);
        info.set_member_treekem_key_package_hash(&stranger, "ab".repeat(32));
        // The invite shape: every seat is held by its hash alone.
        for seat in info.members_v2.values_mut() {
            seat.treekem_key_package_b64 = None;
        }
        info.recompute_state_hash();
        let hash_before = info.state_hash.clone();

        let pending = seat_roster_key_packages_from_welcome(&mut info, &welcome);
        assert_eq!(
            pending,
            vec![stranger.clone()],
            "only the stranger stays hash-only"
        );
        for (id, b64) in &packages {
            assert_eq!(
                info.members_v2[&hex::encode(id.as_bytes())]
                    .treekem_key_package_b64
                    .as_deref(),
                Some(b64.as_str()),
                "the Welcome seats the exact committed package"
            );
        }
        assert!(info.members_v2[&stranger].treekem_key_package_b64.is_none());
        info.recompute_state_hash();
        assert_eq!(info.state_hash, hash_before, "the roster root is unchanged");

        assert_eq!(
            seat_roster_key_packages_from_welcome(&mut info, b"not a welcome"),
            vec![stranger],
            "an unreadable Welcome seats nothing"
        );
    }
}
