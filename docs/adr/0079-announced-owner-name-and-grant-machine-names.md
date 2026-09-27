# ADR 0079: Announced `owner_name` and Grant-Carried Machine Names as ADR-0074 §1 Name Defaults

<!-- File name: docs/adr/0079-announced-owner-name-and-grant-machine-names.md -->

- **Status:** Proposed
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (direction A/B decided 2026-09-27; only David may accept)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** none. It **amends the defaults in Accepted ADR-0074 §1** by
  supersession *if accepted*; ADR-0074 itself is not edited.
- **Superseded by:** none
- **Serves:** vision **R4** (connectivity better than Tailscale: names that work
  with no typing of hex ids) and **R5** (share a subset of my agents: a grantee
  can name what was shared with them)
- **Related:** ADR-0074 §1 (names); ADR-0070 §2 (`ShareGrant` format); ADR-0041
  (`OwnerEnrollment`, synced `machine_name`); ADR-0036 (`human_name`,
  `owner_name`, `X0A4` envelope precedent); ADR-0077 (grant redelivery
  outbox); #960; slice-1 branch `feat/960-s1-names` (`src/names.rs`)

## Context

ADR-0074 §1 says an owner label defaults to "the announced `owner_name`" when a
`ShareGrant` is accepted, and that a shared machine is "labelled at grant
acceptance". Neither can be computed today:

- No `owner_name` is announced. It exists only on signed agent cards
  (`src/groups/card.rs`, v2 domain), which are signed by the **agent** key and
  exchanged out of band.
- A `ShareGrant` (ADR-0070, `src/share_grant.rs`) carries agent ids only, not
  the owner's machine names.

So slice 1 binds owner petnames only from card import or explicitly, and the
grantee labels shared machines by hand (`x0x names machine label`), limited to
machines that host an active granted agent.

Both carriers are strict positional bincode. `UserAnnouncement` is decoded
with `reject_trailing_bytes` and has no magic. `ShareGrant` is decoded strictly
and re-encoded for a canonical-bytes check, and its signature covers a fixed
`signed_bytes()` layout. **Appending a field to either breaks every old
verifier.** `#[serde(default)]` does not help: bincode is not self-describing.
Old peers would drop the announcement, and they would refuse the grant (ACK
withheld, nothing stored). Both carriers therefore need a versioned envelope.
Also, a new DM prefix sent to an old peer falls through to its generic DM
inbox as a junk message and releases a durable ACK, so a new grant envelope
must go only to peers that advertise support for it.

## Decision Drivers

- The ADR-0074 defaults must be computable with no typing.
- A name must never silently point at a key the user did not mean. ADR-0074
  §1 pins names at first use; this ADR keeps that.
- Names must be bound to the owner **user** key, so they cannot be spoofed.
- Old peers must keep working, with no flag day.
- Least new wire under the ADR-0072 scope freeze.
- The owner must be able to keep their name off the network.

## Considered Options

1. **Append optional fields to `UserAnnouncement` and `ShareGrant`.** Rejected:
   it breaks strict decoding and the signatures on every old peer (see
   Context).
2. **Versioned envelopes: a user-signed announcement envelope for
   `owner_name`, and a grant envelope that carries the unchanged v1 grant plus
   a separately signed names section, sent only to capable grantees**
   (chosen).
3. **A `ShareGrant` v2 with a new signature over v1 fields plus names.**
   Rejected: one `grant_id` would then have two different signed forms, so
   receivers need conflict rules, the store format changes, and old owner
   daemons that enforce the grant would need the v1 form anyway.
4. **Take `owner_name` from the `X0A4` identity beat or from cards.** Rejected
   as the primary source. Those are signed by the machine or agent key, not the
   user key. Cards stay as a fallback (see §3).

## Decision

### 1. `owner_name` is announced in a user-signed envelope (decision A)

- **Carrier:** a new `UserAnnouncement` envelope, `X0U3` magic ‖
  bincode(v3 body). It is published on the existing `USER_ANNOUNCE_TOPIC` and
  per-user shard topics. The v3 body is the v2 field set plus
  `owner_name: Option<String>`.
- **Signing:** the **user** ML-DSA-65 key signs
  `"x0x-user-announce-v3" ‖ bincode(unsigned v3 body)`. The domain prefix
  means a v3 signature can never verify as a v2 one, whose unsigned bytes start
  with a `UserId` hash. Verifiers require
  `user_id == SHA-256(user_public_key)`, so the name is bound to the owner key.
  Anyone can claim a *display string*, but no one can attach it to another
  user's key.
- **Compatibility:** an install that announces a name **dual-publishes** the
  unchanged v2 body (no name) and the `X0U3` envelope, as ADR-0036 does with
  `X0A3`/`X0A4`. Old nodes fail to decode `X0U3` and drop it, and lose nothing.
  No change is made to the v2 body or topic.
- **Source and limits:** the value is the ADR-0036 `human_name`, trimmed. It is
  1–128 bytes of UTF-8 with no control characters, the same rule as
  `SelfProfile::validate_name`. A receiver that sees an out-of-bounds name
  ignores the name, not the announcement. Unicode normalization stays
  deferred, as in ADR-0036.

### 2. The grant carries the owner's machine names (decision B)

- **Carrier:** a new typed DM, `x0x-sharegrant-v2\0` ‖ bincode of:
  - `grant: ShareGrant`, the unchanged v1 grant with its v1 signature;
  - `names`: `owner_name: Option<String>` and
    `machines: Vec<{machine_id, machine_name}>`;
  - `names_signature`.
- **What is listed:** the owner install lists each machine that, by its own
  ADR-0041 enrollment and current announcements, hosts at least one of
  `grant.agents` and has a synced `machine_name`. Machine ids are sorted and
  unique, with at most `MAX_GRANT_AGENTS` (64) entries. Names follow §1's
  limits. The worst-case envelope is about 22 KiB, so the decode bound rises
  from 32 to 48 KiB for this prefix only.
- **Signing:** the grant's owner key signs
  `"x0x-sharegrant-names-v1" ‖ SHA-256(grant.signed_bytes()) ‖ owner_name ‖ machines`.
  The encoding has length prefixes, fixed-width ids, and a presence tag for
  `owner_name`. The names are thereby bound to exactly this grant and this
  owner.
- **Receiver:** it verifies `grant` by the unchanged v1 rules and then verifies
  `names_signature` under `grant.owner_public_key`. If either check fails, the
  whole envelope is refused (Malformed, ACK withheld). The grant is stored in
  `share-grants.bin` byte-identical to a v1 delivery, so a v1 and a v2 copy of
  one `grant_id` are an idempotent `Duplicate`. The names go only to the
  grantee's name store.
- **Who gets which envelope:** shared-agent (enforcing) daemons always get v1.
  Grantee agents get v2 only if they advertise support. Support is a signed
  `share_grant_names` capability extension on `DM_CAPABILITY_DIGEST_TOPIC`,
  modelled on #448's `DigestSupportExtension`: same agent key, same
  agent+machine binding, its own sign domain. A grantee that does not
  advertise support, or is unknown, gets v1, and machines are labelled by hand
  as in slice 1. ADR-0077 outbox entries record the envelope version, and a
  retry resends the same bytes.
- The owner can leave out the names section for a grant (`include_names:
  false`, CLI `--no-names`). That grant then goes as v1.

### 3. These are defaults only (amends ADR-0074 §1)

- **Label mapping:** use the slice-1 rule `label_from_display`. Lowercase ASCII
  letters. Each run of whitespace, `_`, `.` or `-` becomes one `-`. Leading
  and trailing separators are dropped. Any other character, an empty or
  over-63-character result, or a reserved label (`me`, `agent`, `machine`)
  gives **no default**, and the user binds the label explicitly.
- **Owner label:** a default applies only when a verified grant is stored or a
  signed card is imported, and only if that `UserId` has no petname yet. The
  sources, in order:
  1. the grant's names section;
  2. the latest verified `X0U3` announcement for that `UserId`;
  3. the card's `owner_name`.

  Seeing an announcement on its own never binds anything.
- **Contact gate:** a stranger can send anyone a grant. So a default is applied
  directly only when the grant owner is a Known or Trusted contact. Otherwise
  it is stored as a *suggestion*, and the local owner applies it with one
  command (`x0x names accept <label>`).
- **Machine label:** for each listed machine that has no label under that
  owner, the default is recorded with source `grant`. Resolution still
  applies the slice-1 check: the machine must currently host an active granted
  agent. Otherwise the name does not resolve.
- **No silent rebinding:** labels and pins stay frozen at first bind. A later
  announced or granted name that differs, or a default whose label is already
  bound to another key or machine, is **reported and not applied**. It appears
  as `default_conflict` in the grant-receipt result, in `GET /names` and in
  `x0x names list`. Only the local owner rebinds, by removing the label first.

### 4. Privacy and visibility

- `USER_ANNOUNCE_TOPIC` is a global gossip topic. An announced `owner_name` can
  be read by **any node on the network**, linked to the `UserId` and, through
  the embedded certificates, to that user's agents. Presence `Social`/`Network`
  visibility filters only local presence queries. It does **not** limit who
  receives the announcement, so the name is effectively public either way.
- User announcements stay opt-in (explicit human consent, as today). On top of
  that, a profile setting `announce_owner_name` (REST
  `PUT /profile`, CLI `x0x profile set --announce-owner-name=false`)
  suppresses `X0U3`, so only the nameless v2 body is sent. When it is `true`,
  the name is announced only while user announcements are enabled.
- The grant names section travels inside an end-to-end encrypted DM, so only
  the grantee's agents see it. It shows machine names only for machines that
  host the shared agents.

## Consequences

### Positive

- The ADR-0074 defaults become computable. A grantee gets `<agent>.<owner>`
  and `machine:<label>.<owner>` names with no typing, which serves R4 and R5.
- Every name is bound to the owner user key, and pins keep their first-use
  guarantee.
- Old peers keep working unchanged: they receive the v2 announcement body and
  the v1 grant.

### Negative / Trade-offs

- Three new wire elements, justified against the ADR-0072 freeze by R4/R5: the
  `X0U3` envelope, the `x0x-sharegrant-v2` prefix, and a capability extension.
- A named install sends two user announcements per publish.
- A publicly announced `owner_name` links a human name to a `UserId`
  network-wide.
- Anyone can announce a look-alike name under their own key. The contact gate
  and the pin/conflict reporting are the mitigation, not the signature.
- Non-ASCII names give no default until Unicode normalization is decided.

### Neutral / Operational

- New name-store fields: `source` (`grant`, `announce`, `card`, `explicit`)
  and pending suggestions. `GET /names` reports conflicts and suggestions.
- `share-grants.bin` does not change format.

## Validation

- Unit tests:
  - the `X0U3` sign/verify round trip;
  - a v2-body replay of a v3 signature fails;
  - a tampered `owner_name` fails;
  - the name bounds hold;
  - an old-shape decoder drops `X0U3` (frozen-struct test, as
    `x0a3_beat_is_byte_identical_to_pre0036_shape`).
- Grant tests:
  - the names signature binds the grant digest, so swapping names between
    grants fails;
  - v1 and v2 deliveries of one `grant_id` are `Duplicate`;
  - a non-capable grantee receives v1 only;
  - the 64-entry and 48 KiB bounds hold.
- Name tests:
  - a default applies once and is never rebound;
  - a conflicting later name is reported, not applied;
  - a stranger's grant only produces a suggestion;
  - a machine default does not resolve after the grant is revoked or expires.
- Mixed-fleet e2e: an old grantee receives a v1 grant and keeps working.
- **Review triggers:** reports of label squatting through look-alike owner
  names, or a Unicode-normalization decision.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
