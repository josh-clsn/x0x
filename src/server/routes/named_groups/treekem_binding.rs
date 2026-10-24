//! The signed `security_binding` of a TreeKEM-bearing event (survivor
//! re-key A1, `docs/adr/transient/T-treekem-bytes-binding-everywhere.md`).
//!
//! The roster commit signs the binding but not the TreeKEM commit bytes,
//! nor an add's display name, KeyPackage hash or Welcome. So a seal names
//! them in the binding:
//!
//! `treekem:epoch=<n>:commit=<blake3 of the commit>:extras=<blake3 of the extras>`
//!
//! An add with a recovery record keeps its `;member-recovery=<hash>` suffix
//! after that. The older forms are still read: `treekem:epoch=<n>` (no
//! bytes named) and upstream #1337's `treekem:epoch=<n>:commit=<blake3>`.
//! [`parse_treekem_binding`] is the one parser for all of them.

use super::{treekem_commit_binding, WelcomeRef, MEMBER_JOINED_RECOVERY_BINDING_PREFIX};

const TREEKEM_BINDING_PREFIX: &str = "treekem:epoch=";

/// A parsed TreeKEM binding. The digests are as written: a caller compares
/// them with the ones it computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TreeKemBinding<'a> {
    pub(super) epoch: u64,
    pub(super) commit: Option<&'a str>,
    pub(super) extras: Option<&'a str>,
    pub(super) recovery: Option<&'a str>,
}

/// Parse a TreeKEM binding. `None` for anything that is not exactly one of
/// the written forms, including an epoch that is not in canonical decimal.
pub(super) fn parse_treekem_binding(binding: &str) -> Option<TreeKemBinding<'_>> {
    let mut parts = binding.split(';');
    let head = parts.next()?.strip_prefix(TREEKEM_BINDING_PREFIX)?;
    let mut fields = head.split(':');
    let epoch_text = fields.next()?;
    let epoch: u64 = epoch_text.parse().ok()?;
    if epoch.to_string() != epoch_text {
        return None;
    }
    let commit = match fields.next() {
        Some(field) => Some(field.strip_prefix("commit=")?),
        None => None,
    };
    let extras = match fields.next() {
        Some(field) => Some(field.strip_prefix("extras=")?),
        None => None,
    };
    if fields.next().is_some() {
        return None;
    }
    let recovery = match parts.next() {
        Some(part) => Some(part.strip_prefix(MEMBER_JOINED_RECOVERY_BINDING_PREFIX)?),
        None => None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(TreeKemBinding {
        epoch,
        commit,
        extras,
        recovery,
    })
}

fn digest_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The Welcome an add carries, by content: its id (the blake3 of its bytes,
/// the same id a [`WelcomeRef`] names) and its length. The inline and the
/// by-reference forms of one Welcome are the same content, so serving an
/// add with its Welcome inlined (`set_inline_welcome`) keeps its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WelcomeContent {
    id: String,
    byte_len: u64,
}

impl WelcomeContent {
    pub(super) fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            id: digest_hex(bytes),
            byte_len: bytes.len() as u64,
        }
    }

    /// The Welcome an event carries. `Err(())` when the inline bytes do not
    /// decode, or name other content than the reference does.
    pub(super) fn of_event(
        inline_b64: Option<&str>,
        reference: Option<&WelcomeRef>,
    ) -> Result<Option<Self>, ()> {
        use base64::Engine as _;

        let inline = inline_b64
            .map(|b64| {
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map(|bytes| Self::of_bytes(&bytes))
                    .map_err(|_| ())
            })
            .transpose()?;
        let referenced = reference.map(|reference| Self {
            id: reference.welcome_id.clone(),
            byte_len: reference.byte_len,
        });
        match (inline, referenced) {
            (Some(inline), Some(referenced)) if inline != referenced => Err(()),
            (Some(inline), _) => Ok(Some(inline)),
            (None, referenced) => Ok(referenced),
        }
    }
}

/// The digest of every field an event applies that the roster commit does
/// not cover. A removal or a ban has none: the digest of the empty tuple.
pub(super) fn empty_extras_digest() -> Option<String> {
    postcard::to_stdvec(&())
        .ok()
        .map(|bytes| digest_hex(&bytes))
}

/// An add's extras (F-2): the display name, the KeyPackage hash, the
/// Welcome, and the owner mandate when the add carries one (A3 review I-1).
/// So a deliverer cannot strip the mandate from an owner-certified add, and
/// the receiver never warn-accepts it as absent. An add with no mandate
/// keeps A1's digest. `JoinRequestApproved` carries no display name and no
/// mandate.
pub(super) fn add_extras_digest(
    display_name: Option<&str>,
    key_package_hash: Option<&str>,
    welcome: Option<&WelcomeContent>,
    owner_mandate: Option<&crate::groups::OwnerMandate>,
) -> Option<String> {
    let welcome = welcome.map(|welcome| (welcome.id.as_str(), welcome.byte_len));
    let bytes = match owner_mandate {
        None => postcard::to_stdvec(&(display_name, key_package_hash, welcome)).ok()?,
        Some(mandate) => {
            let mandate = digest_hex(&postcard::to_stdvec(mandate).ok()?);
            postcard::to_stdvec(&(display_name, key_package_hash, welcome, mandate.as_str()))
                .ok()?
        }
    };
    Some(digest_hex(&bytes))
}

/// The binding a seal writes: upstream's [`treekem_commit_binding`], which
/// names the commit bytes, then the extras.
pub(super) fn treekem_bytes_binding(epoch: u64, commit: &[u8], extras_digest: &str) -> String {
    format!(
        "{}:extras={extras_digest}",
        treekem_commit_binding(epoch, commit)
    )
}

/// The binding a removal or a ban seals.
pub(super) fn treekem_removal_bytes_binding(epoch: u64, commit: &[u8]) -> Option<String> {
    empty_extras_digest().map(|extras| treekem_bytes_binding(epoch, commit, &extras))
}

/// Whether a parsed binding names exactly these bytes and extras at `epoch`.
/// A removal also accepts upstream #1337's form, which has no extras: a
/// removal has none to name.
fn binding_names(
    binding: &TreeKemBinding<'_>,
    epoch: u64,
    commit: &[u8],
    extras_digest: &str,
    extras_optional: bool,
) -> bool {
    binding.epoch == epoch
        && binding.commit == Some(digest_hex(commit).as_str())
        && match binding.extras {
            Some(extras) => extras == extras_digest,
            None => extras_optional,
        }
}

/// Whether a removal's or a ban's binding names these TreeKEM bytes.
pub(super) fn removal_binding_names_bytes(
    binding: &TreeKemBinding<'_>,
    epoch: u64,
    commit: &[u8],
) -> bool {
    binding.recovery.is_none()
        && empty_extras_digest()
            .is_some_and(|extras| binding_names(binding, epoch, commit, &extras, true))
}

/// Whether an add's binding names these TreeKEM bytes and these extras.
pub(super) fn add_binding_names_bytes(
    binding: &TreeKemBinding<'_>,
    epoch: u64,
    commit: &[u8],
    extras_digest: &str,
) -> bool {
    binding_names(binding, epoch, commit, extras_digest, false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_written_form_parses() {
        assert_eq!(
            parse_treekem_binding("treekem:epoch=7"),
            Some(TreeKemBinding {
                epoch: 7,
                commit: None,
                extras: None,
                recovery: None,
            })
        );
        assert_eq!(
            parse_treekem_binding("treekem:epoch=7:commit=aa"),
            Some(TreeKemBinding {
                epoch: 7,
                commit: Some("aa"),
                extras: None,
                recovery: None,
            })
        );
        assert_eq!(
            parse_treekem_binding("treekem:epoch=7:commit=aa:extras=bb;member-recovery=cc"),
            Some(TreeKemBinding {
                epoch: 7,
                commit: Some("aa"),
                extras: Some("bb"),
                recovery: Some("cc"),
            })
        );
        assert_eq!(
            parse_treekem_binding("treekem:epoch=7;member-recovery=cc"),
            Some(TreeKemBinding {
                epoch: 7,
                commit: None,
                extras: None,
                recovery: Some("cc"),
            })
        );
    }

    #[test]
    fn anything_else_does_not_parse() {
        for binding in [
            "",
            "gss:epoch=7",
            "treekem:epoch=",
            "treekem:epoch=+7",
            "treekem:epoch=07",
            "treekem:epoch=7:extras=bb",
            "treekem:epoch=7:commit=aa:extras=bb:more=cc",
            "treekem:epoch=7:commit=aa:commit=bb",
            "treekem:epoch=7;other=cc",
            "treekem:epoch=7;member-recovery=cc;member-recovery=dd",
        ] {
            assert_eq!(parse_treekem_binding(binding), None, "{binding:?}");
        }
    }

    #[test]
    fn a_removal_binding_names_only_its_own_bytes() {
        let sealed = treekem_removal_bytes_binding(3, b"commit").expect("binding");
        let parsed = parse_treekem_binding(&sealed).expect("parses");
        assert!(removal_binding_names_bytes(&parsed, 3, b"commit"));
        assert!(!removal_binding_names_bytes(&parsed, 3, b"other"));
        assert!(!removal_binding_names_bytes(&parsed, 4, b"commit"));
        let upstream = format!("treekem:epoch=3:commit={}", digest_hex(b"commit"));
        let parsed = parse_treekem_binding(&upstream).expect("parses");
        assert!(removal_binding_names_bytes(&parsed, 3, b"commit"));
        let legacy = parse_treekem_binding("treekem:epoch=3").expect("parses");
        assert!(!removal_binding_names_bytes(&legacy, 3, b"commit"));
    }

    #[test]
    fn an_add_binding_names_its_extras() {
        let welcome = WelcomeContent::of_bytes(b"welcome");
        let extras =
            add_extras_digest(Some("Mom"), Some("kp"), Some(&welcome), None).expect("extras");
        let sealed = treekem_bytes_binding(5, b"commit", &extras);
        let parsed = parse_treekem_binding(&sealed).expect("parses");
        assert!(add_binding_names_bytes(&parsed, 5, b"commit", &extras));
        let renamed =
            add_extras_digest(Some("Mallory"), Some("kp"), Some(&welcome), None).expect("x");
        assert!(!add_binding_names_bytes(&parsed, 5, b"commit", &renamed));
        let upstream = format!("treekem:epoch=5:commit={}", digest_hex(b"commit"));
        let parsed = parse_treekem_binding(&upstream).expect("parses");
        assert!(
            !add_binding_names_bytes(&parsed, 5, b"commit", &extras),
            "an add must name its extras"
        );
    }

    #[test]
    fn inline_and_referenced_welcome_are_one_content() {
        use base64::Engine as _;

        let bytes = b"welcome bytes";
        let inline = base64::engine::general_purpose::STANDARD.encode(bytes);
        let reference = WelcomeRef {
            welcome_id: digest_hex(bytes),
            byte_len: bytes.len() as u64,
            source: "00".repeat(32),
        };
        let expected = Some(WelcomeContent::of_bytes(bytes));
        assert_eq!(
            WelcomeContent::of_event(Some(&inline), None),
            Ok(expected.clone())
        );
        assert_eq!(
            WelcomeContent::of_event(None, Some(&reference)),
            Ok(expected.clone())
        );
        assert_eq!(
            WelcomeContent::of_event(Some(&inline), Some(&reference)),
            Ok(expected)
        );
        let other = base64::engine::general_purpose::STANDARD.encode(b"other");
        assert_eq!(
            WelcomeContent::of_event(Some(&other), Some(&reference)),
            Err(())
        );
        assert_eq!(WelcomeContent::of_event(Some("%%"), None), Err(()));
        assert_eq!(WelcomeContent::of_event(None, None), Ok(None));
    }
}
