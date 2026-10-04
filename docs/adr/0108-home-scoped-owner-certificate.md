# ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S2 of [ADR 0088](./0088-group-liveness-contract.md).
- **Amends, upon acceptance:** [ADR 0038](./0038-home-owner-certified-personal-space.md), A Home-scoped owner certificate and a new verdict rule (interim; including the direct disclosure channel that 0038:50–51 excludes); [ADR 0007](./0007-three-layer-identity-model.md), consent for disclosure to Home members only, with two named, ruled exceptions (D68, D96); [ADR 0088](./0088-group-liveness-contract.md) §2, one named entry (D96, §7).
- **Supersedes:** none
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D16, D35, D38, D40, D54, D60, D63, D64, D65, D66, D67, D68, D96; [direction digest](../design/x0x-direction.md); ADR 0085, 0087, 0089, 0093, 0106, 0107; [#1143](https://github.com/saorsa-labs/x0x/issues/1143), [#1023](https://github.com/saorsa-labs/x0x/issues/1023), [#1164](https://github.com/saorsa-labs/x0x/issues/1164), [#1107](https://github.com/saorsa-labs/x0x/issues/1107).

Keep owner-issued certificates in a Home scope and deliver them directly to its members.
An anonymous public announce never invalidates a certificate in that scope.
Every seal still checks certificates until S7 retires those checks after S4 ships.

## Context

The promoted admin in #1143 holds the creator's certificate but cannot seal an add while the creator is offline.
The join stays pending because the creator's public announce is anonymous.
This breaks **L1**: a particular owner device must act despite an online admin holding the evidence.
It also breaks **L2**: anonymity is not on the eight-item may-block-forever list.
D64 makes L3 a hard rule for every slice. §6 lists each block S2 adds or touches and its typed state. The joiner's cause at the 120 s poll still needs a mechanism (Q1).
L4 requires a stated argument for changing the certificate acceptance rule.

Current behaviour is grounded at commit `8b35dd1f447774e1a952166f32910fc41b512623`:

| Current path | Evidence |
|---|---|
| The evidence builder records the latest public digest even when no certificate is present. | `src/server/routes/named_groups.rs:22397–22415` |
| Both the pure failure check and the grace-aware verdict reject embedded bytes when that digest differs. Neither distinguishes an anonymous digest. | `src/groups/mod.rs:1462–1475`, `:1575–1588` |
| The seal gathers evidence for all active seats and refuses a verdict that is not all clean. | `src/server/routes/named_groups.rs:22513–22541`, `:22638–22665` |
| The regression test uses an ordinary PublicRequestSecure + OwnerCertified group, without Home metadata; retain its pending expectation. Add a Home twin with the opposite expectation. | `src/server/routes/named_groups/tests/r19_cert_carry.rs:45–93` (`anonymous_announce_invalidates_hand_installed_cert`) |
| Digest-only seats remain pending until matching bytes hydrate them. Hydration does not change their commitment. | `src/groups/mod.rs:1564–1573`, `:1743–1786` |

#1023 initially asked for another certificate carry while keeping the verdict unchanged.
Its later triage separates missing bytes from #1143's false contradiction.
D54 stops per-case carry patches: S2 changes the rule; S5 owns the general carry and fetch rule.
S2 closes the false contradiction and gives Home evidence a disclosure scope.
It does not close #1023's all-holders-offline case or remove its seal-time structural dependency.
Those parts remain with S5 and S7. ADR 0088's S2 row says “then #1023's structural part”; read it with its S5/S7 rows, not as retirement of the seal dependency in S2.
The [#1023 triage of 2026-10-03](https://github.com/saorsa-labs/x0x/issues/1023) assigns completed carry to #1025/#1056 and the remaining false contradiction to #1143; the general carry and structural retirement stay staged.

D38 derives implied disclosure consent from ownership of this committed Home, not `user_identity_consented`.
That consent survives restart by construction: revalidate Home metadata and policy, rather than restore a global flag.
S2 does not persist the global consent flag, carry certificates on stream/exec/forward/SyncV1 opens, or fix ADR 0070 owner trust ([#1107](https://github.com/saorsa-labs/x0x/issues/1107)).
The restart proof must avoid those owner-trust gates; #1107 is an excluded confounder, not claimed fixed.

## Decision Drivers

- D38 gives consent to Home members only. Public disclosure still needs explicit consent.
- An admin with valid committed evidence must not need the creator's live announce.
- Evidence must survive restart without becoming a public certificate cache.
- S2 must work before S5 and preserve the staged supersessions in ADR 0088.

## Considered Options

1. **Scoped direct evidence plus a scoped verdict** (chosen). Separates disclosure from public discovery and retains the seal gate.
2. **Always publish the owner's certificate.** Rejected by D38's Home-members-only refinement.
3. **Ignore the anonymous digest in the existing global cache only.** Rejected: it supplies no scoped disclosure path and does not implement all of D38.
4. **Add another roster or JoinResult certificate sidecar.** Rejected by D54. S5 owns the single general carry rule.
5. **Remove seal checks now.** Rejected: S7 owns retirement, after S4's bounded revocation enforcement is Accepted and shipped.
6. **Reuse EvidenceV1 Hello/Lookup unchanged.** Rejected: those messages have no Home scope and Lookup permits other relationship contexts.

## Decision

### 1. Scope and certificate identity

"Owner certificate" means an existing owner-issued `AgentCertificate` for a Home seat, including the creator's seat.
Its signature and expiry encoding stay unchanged (`src/identity.rs:487–515`, `:530–542`).
The disclosure context is `(group_id, owner_user_id, subject_agent_id, committed_certificate_digest)`.
Use fixed 32-byte IDs and the roster's BLAKE3 certificate digest, not the public announce digest.
The existing digest hashes canonical bincode certificate bytes (`src/groups/owner_cert.rs:321–329`).

Define a per-group predicate: verified Home metadata covered by the current state hash, policy equal to `home_policy(owner)`, and not withdrawn; serving also excludes deleted or quarantined state.
Use the exact policy check at `src/server/routes/home.rs:68–76`.
Do not use `resolve_home` (`:320–366`): it needs the local user keypair and selects one Home, whereas this predicate works for each committed group without that keypair.
Do not extend implied consent to every ordinary OwnerCertified group or to another Home of the same owner.
S7 owns adoption and election changes; S2 introduces no Tier-1 kind or Home replacement.
An invite alone does not make its holder a member entitled to receive this evidence.
The joiner's existing submission of its own admission certificate stays unchanged.

### 2. Direct delivery on EvidenceV1

Name the ADR 0093 registry-v1 capability **`home_owner_certificate_v1`**.
It means support for this scoped exchange, carrier redaction and Home verdict rule.
Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.
Do not allocate a number or add a registry row here; the accepting PR updates the registry and constants together.
Require both `home_owner_certificate_v1` and `peer_evidence_v1` in a current verified, machine-bound advert before a scoped send.
Unknown, expired, card-only or stored capabilities do not authorize a send.
Refresh the advert through the existing route; expose missing support as retryable `recipient_upgrade_required`.
Do not probe an unknown receiver with certificate bytes; other ADR 0093 sends retain their existing gates.

Reuse stream protocol `EvidenceV1 = 0x06`; retain Put/Ack frame types 7/8 and add the small completion receipt needed to suppress other holders:

| Type | Frozen fixed-integer bincode body |
|---|---|
| 7, `HomeCertificatePutV1` | A vector of 1..K certificate entries, each with four `[u8; 32]` context fields in the order above, then `certificate: Vec<u8>` |
| 8, `HomeCertificateAckV1` | Typed `Accepted`, `Retry(reason)` or `Refused(reason)`, encoded by explicit `u8` tags, with one `u8` reason for Retry/Refused |
| 9, `HomeCertificateReceiptV1` | Four context fields, then recipient `[u8;32]`; no certificate bytes |

K = 1 for S2; S5 (ADR 0111) raises it to K = 4 at its acceptance (D93). The V1 vector shape is frozen now; validate its 1..K bound before accepting any entry. The V1 Ack covers the whole frame, all-or-nothing: Accepted means every entry was stored; any Retry or Refused means none was. A Receipt names one context per entry. So a later K > 1 needs no new Ack shape.
Carry each certificate's existing `to_storage_bytes()` encoding verbatim.
On wire and file intake, require `to_storage_bytes(decoded) == received_certificate_bytes` and recompute the canonical roster digest.
`from_storage_bytes` uses permissive `bincode::deserialize` (`src/identity.rs:810,813`); decoding alone does not reject trailing bytes.
Each Put stream carries one Put and one Ack; a receipt-only stream carries one Receipt with no reply. Types 1–6 and their bodies stay unchanged.
No announcement, advert or user key is added to this body.
Derive each sender/recipient agent from verified current evidence binding it to the live transport machine; refuse an ambiguous binding.
The pre-identity admission of EvidenceV1 alone grants no right to send or receive Home evidence.

Ack has a frozen manual tagged encoding, not bincode's four-byte Rust enum discriminant: Accepted=0; Retry=1; Refused=2.
The reason is a typed `u8`: Retry uses context_unavailable=0, recipient_upgrade_required=1, capacity=2, persistence_failed=3, busy=4, ambiguous_binding=5 (bindings move under ADR 0089, so this must stay retryable); Refused uses invalid_certificate=0, digest_mismatch=1, ineligible=2, malformed=3.
Unknown tags/reasons or extra bytes are protocol errors and never acceptance.
Accepted means durable evidence acceptance, never membership admission or key installation; persist the sender's acknowledgement receipt and stop that pair's retries.
Retry sends no receipt and waits for its named condition to clear; the sender re-attempts only inside its own 30 s slot (D66, below); re-admit each attempt.
Refused terminates that context/recipient delivery, persists the visible terminal cause and cancels retries across reconnect/restart; a newly verified context or eligibility change may create a fresh delivery.
Timeout, lost Ack or transport failure stays unacknowledged and retries idempotently; no transport-layer automatic replay.

Use one designated pusher per context/recipient, with ordered fallback in the D40 pattern; independent all-holder pushes are forbidden.
Ranks come from committed state, never from a node's discovery view (D66, below). A candidate must hold verified matching bytes before it can act.
The first rank gets the first attempt; later ranks get successive fallback slots only after no acknowledged completion in earlier slots. A rank without bytes lets its slot lapse.
The recipient returns Accepted for an already-durable duplicate, then sends Receipt directly to the other N−2 candidate holders to suppress later fallback slots.
Authenticate a Receipt as coming from its named recipient on the live bound machine, require current matching Home context/membership and persist it as an Accepted receipt; a pusher cannot assert another recipient's acceptance. Gate Receipt by the same capabilities; never gossip or forward it. Lost Receipt can permit a counted duplicate in a later fallback slot.
A slot holder alone retries within its slot; a late earlier holder must wait for a new round instead of racing the current rank.

**Slots and rounds (D66).** Each fallback and retry slot lasts 30 s.
- **Anchor.** The anchor of a `(context, recipient)` pair is the signed `GroupStateCommit` that triggered its delivery: the latest commit that created the pair (seated the subject's digest or the recipient) or changed its candidates (seated or removed one). Every node derives it from committed state.
- **Ranks.** Rank the active seats on the anchor commit's verified roster, other than the recipient, by agent ID. Every node with that commit computes the same ranks.
- **Slots.** Slot `s = floor((now − committed_at) / 30 s)`, using the anchor's signed `committed_at` (`src/groups/state_commit.rs:465,495`). A future `committed_at` counts as slot 0. Slot `s` belongs to rank `s mod R`, where R is the number of ranked seats; after the last rank a new round starts at the first.
- **Restart.** Reconnect and restart never reset the anchor, because its proof is durable (below). A restarted node rejoins the shared schedule; it does not start its own.
- **Lapse.** A ranked seat that has left, lacks verified bytes or lacks the two capabilities lets its slot lapse. Each legacy seat therefore adds one lapsed 30 s slot per round.
- **Divergent views.** A node whose view is quarantined, or whose head is not a verified committed state, computes no rank and sends nothing. It shows the typed wait `rank_view_unreconciled` (§6) until verified reconciliation.
- **Skew.** Clock skew can overlap adjacent slots. The result is a counted duplicate that Accepted absorbs.
- **Durable anchor.** `commit_log` keeps only the newest 4,096 commits per group (`COMMIT_LOG_CAP`, `src/groups/mod.rs:753`). An anchor commit and its roster can therefore leave committed history while a pair is still outstanding. Each node keeps its own anchor proof in the S2 sidecar (§5): the signed anchor commit plus the roster projection that its `roster_root` commits to. Ranks and slots derive only from that retained proof, never from `commit_log`. A restart reloads it, so the schedule survives both restart and history truncation.
- **Missing proof.** A node with no verified anchor proof for a pair computes no rank and sends nothing for that pair. It shows the typed wait `anchor_unavailable` (§6). How such a pair resumes is open question Q2.

A slot grants no authority. Every send still passes the eligibility checks in §4, and the receiver's checks are unchanged.
New committed seats, reconnects and eligible seal retries make a node check its unacknowledged `(context, recipient)` pairs; it sends only in its own slot. Persist receipts in the scoped sidecar before suppressing work across restart.
Lost receipt persistence can cause duplicates in later fallback slots; Accepted is idempotent and restores the receipt. It never causes an all-holder burst.
Sealing does not wait for all recipients to acknowledge.
S5 (ADR 0111) reuses this Home push and its scope rather than starting a parallel push; it adds its general retrieval/inline-K rule without duplicate distributions. Any later retirement of this push needs an explicit successor decision.

#### Existing certificate carriers: Home egress is part of S2

| Carrier today | Home rule under S2 |
|---|---|
| #970 `JoinResult.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: serve only directly to the currently committed, authenticated recipient under ADR 0107; no public blob or gossip fallback. |
| #1023 `MemberAdded.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: retain in guarded direct member copies; drop from the gossip copy. |
| `MemberJoined` admission certificate and `MemberAdded.certificate_b64` (joiner's own certificate) | Retain on the gossiped copy as a **named interim exception, ruled by David (D68)**. It stays until S5 (ADR 0111) removes it; guarded direct copies stay unchanged. |
| #946 `GroupCertFetchResponse.cert_json_b64` | **Named, ruled, time-limited exception (D96, §7)**: upgraded Home holders keep answering #946 as today, including metadata-topic answers, until D35's minimum supported version drops the peers that need it. |

The #1023 sidecar is built at `src/server/routes/named_groups/seat_cert_fetch.rs:696–732,752–789`, attached at `named_groups.rs:14061`, and published with `certificate_b64` at `:14051,14080`; equivalent publish paths include `:19290,19298,19562,19570`.
#946 currently publishes answers at `seat_cert_fetch.rs:403–425`; its topic answers are the D96 exception (§7).
The joiner's own certificate is on `MemberJoined` at `named_groups.rs:33647`, published at `:33685` and re-sent at `:33482`. ADR 0028 relays that signed event unchanged, so the certificate cannot be stripped. Every receiver rejects an OwnerCertified `MemberAdded` without `certificate_b64` (`named_groups.rs:11249–11255`); dropping it would introduce a new acceptance rule. Both joiner-certificate fields therefore remain the named interim exception.
David ruled that S5 owns that change (D68). S5 (ADR 0111) adds the digest-only-add rule, with its security argument and mixed-version plan, and fills the bytes by fetch-by-hash. S2 adds no rule for these fields. The exception ends where S5's rule is in effect, under S5's mixed-version plan: in a Home where every active seat and the joiner set S5's capability in a current verified advert. In a Home with any seat that lacks it, or whose advert is unknown, the exception continues until that seat upgrades or leaves, or until D35's minimum supported version.
Exposure until then: each Home join publishes the joiner's own owner certificate on gossip, where non-member mesh peers receive it. The certificate links the owner's user ID to that agent.
The metadata topic is plaintext and its mesh can contain non-members (`src/gossip/pubsub.rs:1203–1228`, non-member-mesh test around `:5072`); a topic subscription is not membership authentication.
Redact only the gossip projection, retaining the committed certificate digest and signed commitment; never rewrite signed bytes. Apart from the two named exceptions (D68 joiner certificate, D96 #946), if any nested artifact contains certificate bytes, withhold that artifact from gossip and deliver it directly under the same guard.
Audit all event, state/snapshot, recovery, blob and retransmission serializers for nested copies; apart from those two named exceptions, no owner-certificate bytes may leave a Home node except to a directly authenticated member of that Home.
The joiner's existing submission of its own admission certificate remains unchanged (it is gossiped; see the D68 exception above).
S5's K inline certificates follow the same Home rule. S5 ends the D68 exception, and its general carry rule cannot restore other gossip leakage.
Legacy nodes can still leak through today's carriers: upgraded nodes enforce this rule on every own write, and S2 makes no fleet-wide privacy claim while legacy senders remain.

### 3. Size before implementation

The fixed ML-DSA-65 sizes are 1,952 bytes per key and 3,309 bytes per signature (`src/upgrade/signature.rs:14–17`).
The three vectors add 24 bytes of lengths; issuance adds 8 bytes.
The expiry encoding and storage marker follow `src/identity.rs:766–804`.
These are calculated encoded sizes at S2 K = 1, not measured transport throughput; Put includes the outer certificate-entry vector's 8-byte length prefix.

| Bytes | No expiry | With expiry |
|---|---:|---:|
| Canonical certificate for roster hashing | 7,246 | 7,254 |
| Certificate storage bytes carried by Put | 7,245 | 7,258 |
| Put at K=1, including 8-byte entry-vector length, 128-byte context, 8-byte certificate-vector length, 5-byte frame and 1-byte protocol prefix | 7,395 | 7,408 |
| Accepted Ack (5-byte frame + 1-byte tag; same EvidenceV1 stream) | 6 | 6 |
| Retry/Refused Ack (adds one reason byte) | 7 | 7 |
| Put plus Accepted Ack | **7,401** | **7,414** |
| Put plus Retry/Refused Ack | 7,402 | 7,415 |
| Receipt (160-byte body + 5-byte frame + 1-byte protocol prefix) | 166 | 166 |

With one designated pusher, the successful no-loss costs below use the worst-case expiring certificate. Put/Ack costs include Accepted Acks; the total column also counts one 166-byte Receipt to each other candidate. These are not transport throughput or a loss-independent bound.

| Distribution at N active seats | Put/Ack pairs | N=5 Put/Ack bytes | N=5 receipt bytes | N=5 total application bytes |
|---|---:|---:|---:|---:|
| One changed certificate to all other seats | N−1 | 29,656 | 1,992 | 31,648 |
| One cold member gets the N−1 existing certificates | N−1 | 29,656 | 1,992 | 31,648 |
| Initial complete fleet distribution | N(N−1) | 148,280 | 9,960 | 158,240 |
| Reconnect/fleet restart with all Accepted receipts durably stored | 0 | 0 | 0 | 0 |
| Restart with q unacknowledged pairs (q≤20 for one N=5 distribution) | q | 7,414 × q | 498 × q | 7,912 × q |
| One duplicate/fallback wave covering all fleet pairs after lost Acks/receipts | N(N−1) | 148,280 | 9,960 | 158,240 |
| All-local, acknowledged seal | 0 | 0 | 0 | 0 |

Receipt traffic is `166 × (N−2)` per successful pair; N=2 has no other candidate to notify.
Each Retry/Refused adds one byte to its attempted pair; a lost Ack costs the Put alone, and each actual retry/fallback adds a separately counted exchange.
The rejected all-holder policy costs `(N−1)^2` pairs (118,624 bytes at N=5) for one cold member, and `N(N−1)^2` pairs (593,120 bytes) for a fleet restart without receipts.
Designation removes that sender multiplier; losses, changed rosters and fallback rounds can still add duplicates. Do not claim a universal traffic bound under faults.
A seal retry distributing q eligible unacknowledged pairs costs `[7,414 + 166 × (N−2)] × q` on success; verification remains per active seat.
QUIC/TLS overhead, capability refresh and existing commit/Welcome traffic are excluded. Every failed attempt, repeated Receipt or capability exchange must be counted separately; no coordination traffic is hidden in the successful totals.
Each V1 Put carries a vector of 1..K certificate entries, with K = 1 for S2; S5 (ADR 0111) may raise K at its acceptance. Do not repeat acknowledged bytes in every seal.
Keep ADR 0089's 32 KiB frame cap, 5 s deadline, per-machine stream/rate limits and global budgets; charge all frames to them.
Fair scheduling by Home, the 16 MiB file cap and pruning are ruled (D67); §5 states them.

### 4. Verdict and L4 security argument

Add scoped bytes as an extra committed-bytes source in `OwnerCertEvidence`, selected only by the per-group Home predicate and matching committed seat digest.
Evaluate `owner_cert_verdict(&mut self, ...)` on the real roster, not a hydrated clone: preserve its stamps and clears of `certificate_missing_since_ms` (`src/groups/mod.rs:1509,1538–1542,1595–1600,1630–1635`).
Matching scoped bytes satisfy the digest-only seat before its DigestPending branch; they leave the roster root and legacy byte fields unchanged.
The two production evaluation sites are `src/server/routes/named_groups.rs:21305,22638`; `owner_cert_admission_failures` (`src/groups/mod.rs:1432`) has no caller today, but keep its pure semantics consistent.
Newly scoped bytes persist only in the scoped file, never in legacy roster or public-cache files.
Re-check owner, subject, signature, expiry and current revocation at each use.
Use the existing verifier (`src/groups/owner_cert.rs:345–380`).

**Acceptance rule relaxed:** for this Home verdict, the canonical anonymous public digest is absence of public disclosure.
It is never a contradiction, never a warranted certificate fetch, and never starts missing-evidence grace for an otherwise valid scoped certificate.
A valid matching scoped or roster-embedded certificate yields `Clean` despite that anonymous digest.
A different certificate-bearing public digest retains today's stale-evidence handling; S2 does not decide certificate rotation policy.
Absent bytes stay pending. Invalid, wrong-owner, wrong-agent, expired or revoked evidence never becomes clean.
Ordinary groups retain their current rules.

An anonymous digest now has the same effect as no discovery entry, which already permits clean committed evidence (`src/groups/mod.rs:1463,1576`).
Only the subject agent's authenticated bound machine can sign its announce; an arbitrary third party cannot manufacture this absence signal.
Residual risk: an anonymous announce after re-issue erases the public rotation signal, so an older, valid committed certificate can seat again. S2 neither detects nor solves that rotation case; revocation remains the kill switch (`src/groups/owner_cert.rs:337–344`).

The security argument is separation of consent scopes: anonymity says nothing about the owner's signed binding inside Home.
Transport delivery adds no authority to the certificate; the owner signature and committed digest establish it.
No signature, sender-authority, prev-hash, owner-mandate, fork, revocation or TreeKEM adoption check is relaxed.
Seals still require all active seats clean; missing evidence is not permission to seal.

Before every Put or resend, require sender, subject and recipient to be active in this Home and not banned or revoked.
For third-party certificates require current Clean sender/recipient evidence and valid current machine bindings.
Allow a self-subject Put (`subject = sender`): verify the sender's own certificate against its committed digest and owner, and allow an active committed recipient with a current authenticated binding even if its own certificate bytes are DigestPending.
Check bans, agent/machine/binding revocations, known expiry and definitive invalid evidence; this narrowly scoped certificate bootstrap avoids the mutual-digest deadlock. It grants no Clean verdict, admission or class-K entitlement to the recipient.
Refuse withdrawn, deleted or quarantined Home state.
Apply ADR 0107's serving guard to every join/recovery artifact and D60 to class-K material: “every delivery and resend requires current recipient eligibility and the current secret epoch” (David, 2026-10-03), including agent/machine/binding revocation, expiry, verdict change and quarantine.
For scoped-only Home seats, ADR 0107 uses its permitted current `Clean` verdict alternative, computed from scoped committed bytes; it does not require writing those bytes into the roster or use discovery as authority.
The self-subject Put bootstrap exception cannot authorize a join artifact, Welcome or K share.
Linearize selection, the immediate pre-write eligibility/epoch check, and each physical exchange with membership invalidations under the Home membership lock; re-admit every resend.
Track and cancel in-flight disclosure before removal, ban or deletion commits; check current revocation, expiry and bindings at each transport handoff.
Use one bounded direct QUIC exchange with no hidden resend, gossip fallback or relay.
The receiver repeats these checks against its verified local committed roster; missing context is retryable and grants no evidence authority.
Keep scoped bytes out of public announces, public blob fetch, AgentCards, general EvidenceV1 Lookup and unrelated grant/trust views.
Any existing output fed by scoped bytes must enforce this same disclosure scope; already delivered bytes cannot be recalled from a former member.
The [join-artifact lifecycle note on #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is related work on serving and egress only.
S2 does not depend on that branch, its caches or its implementation.

### 5. Persisted state and mixed versions

Use a separate `<data_dir>/home-owner-certificates.hscert`, new extension and magic **`X0HCV1\0\0`**; old binaries do not scan this extension.
Freeze the V1 body as five ordered vectors:
1. certificate entries (four context fields, storage-byte vector);
2. Accepted receipts (four context fields, recipient `[u8;32]`);
3. terminal Refused deliveries (four context fields, recipient `[u8;32]`, typed `u8` refusal reason);
4. outstanding pairs (four context fields, recipient `[u8;32]`, anchor key `[u8;32]`);
5. anchor proofs (anchor key, then the proof below).

Sort each vector by its fixed-field tuple. Reject duplicates, conflicting Accepted and Refused entries, a pair that is also Accepted or Refused, a pair whose anchor key has no proof, and a proof that no pair references. A newly verified context/eligibility change clears the obsolete refusal atomically; restart alone does not.

**Anchor proofs (D66).** They keep each outstanding pair's schedule independent of `commit_log` retention.
- **Key.** The anchor key is the 32 bytes that the anchor's `state_hash` hex decodes to. Refuse a `state_hash` that does not decode to exactly 32 bytes.
- **Proof.** Store the signed commit fields byte-for-byte as signed, in `signable_bytes` order (`src/groups/state_commit.rs:476–497`), then `signer_public_key` and `signature`. Then store the roster projection entries sorted by agent ID: agent ID string, role byte, state byte, optional certificate-digest string, each exactly as `roster_root` hashes it (`:107–130`). Never re-encode a hashed or signed field.
- **Check at load and at use.** The signature verifies (`verify_structure`, `:554`). The projection re-derives the commit's `roster_root` (`roster_root_of_projection`, `:184`, as `RetainedCommit::roster_root_consistent` does at `:237`). The commit's group matches the pair's context, and its revision is not above the node's verified head. A proof that fails makes the file `corrupt` (§6) and is never used.
- **Capture.** When a node applies a commit that creates or re-anchors outstanding pairs, it writes their pair records and the new proof in one atomic sidecar write, before its first send for those pairs. The proof comes from the commit being applied, so capture needs no history lookup. At startup, a node captures any outstanding pair that has no record from `commit_log` if its anchor is still there; otherwise the pair is `anchor_unavailable` (Q2).
- **Lifetime.** Remove a pair record in the same atomic write that persists its Accepted receipt or Refused delivery, re-anchors it, or prunes it under D67. Remove a proof once no pair references it. Never remove a proof that an outstanding pair references.
- **Size.** About 12 KB per proof for a 5-seat Home with today's hex fields; the signature and signer key are most of it. Each pair record is 192 bytes. A Home usually has one live proof, because any seat change re-anchors every outstanding pair. Proofs count toward the 16 MiB cap. A proof that would exceed it is not written, and its pairs wait as `retry(capacity)`.

Use `DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()` for wire and file bodies, with bounded decoding (`src/evidence_wire.rs:45–50`); bare DefaultOptions is varint.
Require exact body consumption and canonical certificate re-encoding equality on file as on wire; validate signatures/commitments before use and membership/revocation again at use.
Persist accepted bytes before Accepted Ack, and sender receipts before durable retry suppression: temp file, fsync file, atomic rename, fsync directory (ADR 0089 §3). A write failure yields Retry(persistence_failed); duplicate Put is idempotent.
Do not append fields to `peer-evidence.bin` or persist derived `Clean` verdicts.
Retain ADR 0089's 10 KiB certificate limit.

**Cap, pruning and fairness (D67).**
- **Cap.** The file holds at most 16 MiB, about 2,270 entries at 7.4 KB each. A Put that would take it past the cap answers `Retry(capacity)`, stores nothing and leaves the file unchanged. Capacity pressure never yields usable unverified evidence.
- **Pruning.** Prune a certificate entry, Accepted receipt or Refused delivery only after a verified commit invalidates the membership of its subject or recipient in this Home: removal, ban, revocation, withdrawal or a signed Home delete. Never prune for an active seat. A quarantined or unreconciled view never prunes. Pruning uses the same atomic rewrite as any other change.
- **Fairness.** Schedule Puts, Receipts and intake fairly by Home inside ADR 0089's existing per-machine and global budgets. When several Homes have due work, serve them round-robin by Home, so no Home starves another. S2 adds no new rate or budget.

Keep `named_groups.json` and `home-suite-groups.json` in their unchanged legacy-safe JSON formats (#451); do not place scoped bytes or new fields there. S2 writes no legacy-view placeholder; existing #451 behaviour is unchanged.
Defer any first sidecar write that changes host behaviour until ADR 0094's host commit where applicable.
Follow ADR 0085: new magic for a changed body, frozen released decoders, lazy rewrite, atomic replace and released-binary fixtures.
No released binary yet writes X0HCV1: before code merges supply a golden encoder fixture, covering all five vectors including anchor proofs, plus SHA-256 and provenance; the first release writing it supplies the actual released-binary fixture, retained by every later decoder test.
Unknown or corrupt formats are reported as `home_cert_store_unavailable` (§6) and left byte-identical; disable writes to that path until repaired (ADR 0085 rule 4, ADR 0089).
Older binaries ignore this separate file and keep today's verdict; re-upgrade validates and reuses it.
They may still reproduce #1143. Downgrade never implies successful Home recovery.

New to old: send no scoped frames without `home_owner_certificate_v1`; Home certificate gossip stays redacted even for a legacy receiver except for the two named exceptions (D68, D96); keep existing join/commit formats and their limitations. A legacy seat is still ranked, and its slot lapses (D66). #946 runs unchanged in both directions (D96).
Old to new: old announces and commits decode unchanged; a committed valid Home certificate survives anonymous announces under the new verdict.
New code does not infer fresh capability bits from stored evidence.
One upgraded admin with the required bytes can pass its seal gate; legacy admins retain the old refusal.
This is not a claim that every mixed-version Home converges before S5–S7.

### 6. Typed blocks (L3, D64)

D64 makes L3 a hard rule: every block S2 adds or touches ends in a typed refusal or a typed, visible wait that names what it waits for.
Authority and sender states show on the existing `/diagnostics/groups` surface (`src/api/mod.rs:674`). The joiner's state shows on `/groups/:id/join-status` (`:1309`).

| Block | Typed state | Names | Exit |
|---|---|---|---|
| Home seal with an active seat whose committed digest has no local bytes | `OwnerCertMemberPending` (existing), recorded per join attempt | subject agent ID, committed digest, that pair's delivery state | matching bytes from one holder (L1). All holders offline is §2 item 8 |
| Joiner's 120 s TreeKEM poll while that seal waits | `TimedOut`; today it names no cause | must name `owner_certificate_pending` | Q1, which blocks acceptance |
| Pair waiting for its slot | `awaiting_slot` | anchor commit, rank, slot start | its slot starts, or Accepted or a Receipt lands |
| Pair after `Retry(reason)` | `retry(reason)` | the reason's condition, listed below | the condition clears; the next attempt is in the holder's slot |
| Pair after `Refused(reason)`, or after the sender's own eligibility check fails | `refused(reason)`, persisted and terminal | the reason | a newly verified context or eligibility change starts a fresh delivery. A deleted Home is §2 item 5 |
| Quarantined or unverified view | `rank_view_unreconciled` | local head or quarantine marker | verified reconciliation |
| Pair with no verified anchor proof (§5) | `anchor_unavailable` | the pair, and its anchor key when known | Q2, which blocks acceptance |
| Full sidecar | `Retry(capacity)` to the sender | `capacity` | pruning after a membership invalidation (D67) |
| Unreadable sidecar | `home_cert_store_unavailable`, with `unknown_format` or `corrupt`; intake answers `Retry(persistence_failed)` | the file and its fault | a binary that reads that format, or an operator moves the file aside (ADR 0085 rule 4, ADR 0089). Other holders still serve the group (L1) |
| Joiner without S5's capability, all holders offline for 10 minutes | the #946 `certificate_evidence_unavailable` refusal | see §7 | see §7 |

Each Retry reason names its condition:
- `context_unavailable`: the recipient lacks the committed context. It names the anchor commit.
- `recipient_upgrade_required`: a current advert with both capabilities. This is an upgrade wait.
- `capacity`: free space in the recipient's sidecar.
- `persistence_failed`: a durable write.
- `busy`: room in the ADR 0089 budgets. This is a backoff wait.
- `ambiguous_binding`: one verified machine binding (ADR 0089).

No S2 block is a bare pending state. Sealing never waits for push acknowledgements.

### 7. Named, ruled exception: #946 in Home (D96)

David ruled to keep #946 for legacy peers until D35's minimum supported version drops them (D96). He chose this against the recommendation, which was to retire it early in Home.
S2 treats every other Home scope leak as a security defect. This one is a named, ruled, time-limited exception, not a precedent.

**Mechanism.** S2 does not change #946.
- Upgraded Home holders keep answering #946 requests on the metadata topic as today.
- Authorities keep staging the 10-minute `certificate_evidence_unavailable` refusal (`CERT_EVIDENCE_DEADLINE_MS`, `seat_cert_fetch.rs:55`) for joiners without S5's capability. Before S5 ships, no peer has that capability.
- S5 (ADR 0111) defines which requesters still get #946 answers once it ships.

**Exposure, stated plainly.**
- Each #946 answer in a Home publishes one owner certificate, JSON-encoded, on the Home's plaintext metadata topic. Each responder sends at most one answer per digest per group every 30 s (`seat_cert_fetch.rs:45`).
- Every peer in that topic's mesh receives it, including non-members (`src/gossip/pubsub.rs:1203–1228`).
- The certificate carries the owner's user public key, the subject agent's public key and the owner's signature (`src/identity.rs:487–515`). Any receiver can link the owner's user ID to that agent. An anonymous public announce withholds exactly this link, and D38 limits it to Home members.
- Delivered bytes cannot be recalled.
- While any peer still needs #946, S2 makes no Home privacy claim against non-member mesh peers.
- **End date.** The exception ends when D35's minimum supported version drops the last release that needs #946. D35 has not yet published that version, so no end date is fixed today.

**L4.** No acceptance rule is relaxed. The exposure is to privacy, not authority. A received certificate proves only the owner's existing signed binding. A Home verdict accepts bytes only against the committed digest of an active seat, so a non-member gains no evidence authority.

**Amendment to ADR 0088 §2.** This ADR amends ADR 0088 §2 with one named entry, ruled by David (D96):
- **#946 legacy refusal.** A joiner without S5's capability may receive a terminal refusal after 10 minutes of continuous digest-only seal refusals, although §2 item 8 says such a fetch waits.
- **Typed state:** the existing signed `JoinRefusalReceipt` with reason `certificate_evidence_unavailable` (`JoinRefusalReason`, `named_groups.rs:1234–1247`; staged at `:33871`). The joiner sees `Refused` with that reason in `last_join_outcome` on `/groups/:id/join-status`. The authority records it on `/diagnostics/groups`.
- **Exit:** for that attempt, an admin issues a fresh invite once a holder is online. The entry ends at D35's minimum supported version. S5 already drops this refusal for peers with its capability.
- **Residual:** a released TreeKEM joiner's 120 s poll ends before the refusal is staged, so it sees today's cause-free `TimedOut`. Released binaries cannot change, so D64 can bind only upgraded joiners here (Q1).

This is one §2 entry. If ADR 0111 also records D96, both ADRs name this same entry.

**Mixed versions.** Legacy and upgraded nodes keep exchanging #946 as today. Legacy Home members keep their only certificate fetch.

## Consequences

- **Positive:** anonymous public identity and an offline creator no longer defeat locally held Home evidence.
- **Trade-off:** scoped persistence and guarded direct delivery add work; legacy peers and unavailable bytes retain limitations. Each fallback rank can add 30 s, and each legacy rank adds a lapsed slot (D66).
- **Trade-off (D68, D96):** two named owner-certificate exposures to non-member mesh peers remain. The joiner's own certificate stays on Home gossip until S5 removes it, and in a Home with any seat lacking S5's capability until that seat upgrades or leaves, or until D35's minimum supported version. #946 answers stay until D35's minimum supported version, which has no published date yet.
- **Operational:** no release date is promised from the size calculation. Outside the two named, ruled exceptions (D68, D96), scope leaks are security defects, not Home known limitations.

## Validation

The W3-H harness (#1164) does not exist yet; these are specified cases, not claimed runs. Recommend a dedicated S2 tracking issue linked to #1164.
Each red case must be committed and shown red on main before S2 code merges; in-process red tests alone do not satisfy D16/D54.
Run daemon cases only in the isolated loopback-only Linux namespace; macOS fails closed.
All cases use a deterministic clock t=0, public create/admit/promote/invite/redeem APIs, and a scheduled transport that records every write; advance time only at the named barriers. Fixtures prepare signed metadata/capabilities, never inject discovered certificate bytes.

- **`s2_home_anonymous_owner_offline` (red baseline):** nodes O (creator), X (holder), A (promoted admin), J (joiner). At t=0 create Home O, admit X/A and commit A's promotion; deliver O's certificate through the actual member path and verify its digest on A. At t=1 O emits a machine-signed anonymous announce; deliver it to A, then disconnect O. At t=2 redeem J's valid A-issued invite with other evidence already present. Main returns OwnerCertMemberPending for O; S2 completes the authoritative add and J's Welcome/key installation without O. Anonymous public output stays unchanged. Repeat with creator/admin identities permuted.
- **`s2_home_scoped_evidence_restart` (red baseline, store isolation):** same nodes; at t=0 drive the trimmed-sidecar shape of `trimmed_member_added_all_holders_offline_stays_pending` (`r19_cert_carry.rs:1329`), but keep X online with O's bytes. A is seated/promoted from a real trimmed MemberAdded and has only O's committed digest; no JoinResult, #946 answer or discovery entry may supply O's bytes. At t=1 X establishes the authenticated binding and sends the real scoped Put; A persists it before Accepted, then disconnect O/X and restart A at t=2 with empty discovery and unchanged digest-only legacy roster. At t=3 redeem J's invite and seal using only the new sidecar as O's byte source. Main remains pending/no scoped durable recovery; S2 seals and installs J's keys. Delete/disable only the new sidecar in a negative run and require pending again. Avoid ADR 0070 owner-trust APIs; #1107 is excluded. Keep the old membership-carried restart shape as a separate red verdict reproduction, not evidence for the new store.
- **`s2_home_ordinary_group_twin` (control + red):** nodes A/J, clock t=0; create the ordinary PublicRequestSecure + OwnerCertified shape via APIs. Preserve `anonymous_announce_invalidates_hand_installed_cert` as the fail-closed ordinary-group control. At t=1 deliver A's own signed anonymous announce; its seal stays pending on main and S2. Repeat with committed Home metadata/policy: only that twin changes from red/pending to Clean and successful seal. Exercise both production verdict sites and assert real-roster grace stamps survive evaluations/restart.
- **`s2_home_all_egress_privacy` (red baseline):** O/X/A plus stranger S, grant-only G, invite-only J and other-Home H; t=0 create the memberships and attach S to the non-member topic mesh. At t=1 drive each #970, #1023, MemberJoined admission certificate (publish and resend), MemberAdded.certificate_b64 and #946 carrier, the ADR 0028 unchanged MemberJoined relay, all gossip publish/recovery/blob paths, and Put. Capture EVERY egress, including publishes before mesh delivery, and decode nested JSON/base64/bincode/storage encodings. Search every byte string/candidate certificate for a canonical digest equal to ANY Home member certificate, including locally held/embedded bytes rather than only the new store. Main leaks to the topic; S2 explicitly permits only the joiner's own certificate on gossiped MemberJoined (including its unchanged ADR 0028 relay) and MemberAdded.certificate_b64 under the named D68 exception (until S5 is in effect), plus today's #946 answers under the named D96 exception (§7). Assert those exceptions explicitly; every other certificate egress on gossip is forbidden and certificate bytes otherwise leave only on bound direct member channels. At t=2 race removal/ban/withdrawal/expiry/agent-machine-binding revocation/verdict/quarantine and connection replacement with writes; no subsequent cancelled send/resend may leak. K paths also require the current epoch. Record public announces/cards/Lookup unchanged.
- **`s2_home_designated_push_and_ack` (control for counts, red for new protocol):** five active nodes, t=0 commit one shared delivery trigger and freeze candidate ranks; all hold the same certificate. Deliver first-rank traffic before fallback and require four Puts, 29,656 Put/Ack bytes plus 1,992 Receipt bytes, total 31,648 application bytes; deliver/persist all receipts before later slots. Give a cold recipient four existing certificates and require four Puts, not sixteen. Restart all nodes after fsync'd Accepted receipts: zero certificate re-push. Delay or drop Receipt and assert only the named recipient can authorize retry suppression; count the resulting fallback duplicates. In separate schedules lose Put, Ack or receipt fsync; advance the shared clock by the ruled 30 s slot (D66), admit only the scheduled rank, and count every duplicate. Exercise each typed Retry/Refused reason: condition-cleared retry, terminal cancellation, no receipt on failure and no false membership confirmation. Two digest-only nodes exchange self-subject Puts through authenticated bindings without a mutual-cert deadlock; the exception never releases K/join artifacts.
- **Exit/non-regressions (controls):** with one holder/admin reachable and no faults, complete each Home add within the existing 120 s TreeKEM window; loss/fallback scenarios use the D66 schedule and expose the §6 typed states. Preserve ADR 0106 carry and ADR 0107 serving guards. Keep wrong-owner/agent, signature, expiry, revocation, commitment mismatch, non-anonymous replacement, fork/TreeKEM-adoption exclusions and ordinary groups fail-closed. All holders offline stays a typed, retryable seal wait under 0088 §2 item 8, except the D96 entry (§7) for a joiner without S5's capability; return one holder and resume without owner bypass. Cover malformed/duplicate/oversize frames, canonical re-encoding, trailing bytes, deadlines, budgets and fairness.
- **Mixed versions/storage (controls):** at t=0 pair candidate with released v0.45.0/v0.46.0 in both directions and a peer advertising only `peer_evidence_v1`; no new frame without `home_owner_certificate_v1`, no certificate-bearing Home gossip fallback outside the D68 and D96 exceptions, legacy verdict limitations visible, and a legacy rank's slot lapses (D66). After t=1 accepted Put/fsync, crash before/after file rename, directory fsync and Ack; restart with empty discovery, lose Ack, downgrade, then re-upgrade. Old binaries start on unchanged legacy JSON and leave `.hscert` byte-identical; unknown/corrupt magic stays intact with writes disabled. Downgrade across more than 4,096 commits, then re-upgrade: retained anchor proofs reload; a pair created while downgraded is captured from `commit_log` if its anchor is still there, and is otherwise `anchor_unavailable` (Q2). Load golden and, once available, first-released X0HCV1 fixtures with SHA-256 checks.
- **`s2_home_push_rounds` (red baseline; D66):** nodes R (cold recipient) and holders P1–P4, ranked by agent ID; all hold the same verified certificate. At t=0 commit C seating R, with `committed_at` = 0. The schedule drops P1's Put at t=0. At t=15 s restart P2 and reconnect every node; deliver P2's Put at t=30 s. Assert: P2 sends nothing before t=30 s, its slot follows C's `committed_at` and not its restart, each slot has exactly one sender, and R's Receipts suppress P3 and P4. Variants: (a) P1 runs released v0.46.1, its slot lapses, and P2 sends at t=30 s; (b) P3 is quarantined, never sends, shows `rank_view_unreconciled`, and the others' schedule is unchanged; (c) P2's clock runs 40 s fast, which gives one counted duplicate, an idempotent Accepted and no new authority; (d) at t=20 s commit C2 removing P2, and every node re-anchors to C2. Main has no scoped push, so the case is red.
- **`s2_home_store_cap_and_prune` (red baseline; D67):** node A in Homes H1 and H2, holder X. At t=0 seat H1 members through the public APIs until delivered certificates fill A's sidecar to within one entry of 16 MiB. At t=1 X's next Put gets `Retry(capacity)` with the file byte-identical and no Accepted. At t=2 commit removal of ten H1 seats; A prunes only their entries and receipts in one atomic rewrite. X's next-slot Put then gets Accepted. Assert that no active seat's entry is ever pruned, that a quarantined A never prunes, and that a crash during the prune rewrite leaves the old or the new file whole. Fairness: give H1 and H2 due pairs above ADR 0089's per-machine budget; sends alternate by Home and both drain. Main has no sidecar, so the case is red.
- **`s2_home_typed_waits` (red baseline; D64):** nodes O, X, A and J. At t=0 create the Home with O's bytes on X only and A digest-only for O. Drive each §6 row with scheduled faults: drop X's Puts, take every holder offline, quarantine A, corrupt the sidecar, fill it, and withhold one capability. Assert that each typed state appears on its named surface with its cause by the next poll, and that no block shows a bare pending state. J's `TimedOut` at t=120 s must name `owner_certificate_pending`; this row is written to Q1's ruled mechanism. Main shows a cause-free `TimedOut` and no pair states, so the case is red.
- **`s2_home_946_legacy_exception` (control; D96):** A (S2 authority), X (S2 holder), L (released v0.46.1 TreeKEM joiner), L2 (released non-TreeKEM joiner) and S (non-member on the metadata topic mesh). At t=0 create the Home with A digest-only for O. Schedule 1: L redeems an A-issued invite, A publishes the #946 request, X answers on the topic, and A seals. Assert that S receives that answer, at most one per digest per responder per 30 s, and no other certificate. Schedule 2: X is offline before the join. L's poll ends at t=120 s in a cause-free `TimedOut`; at t=600 s A stages the signed `certificate_evidence_unavailable` receipt, and L2 sees `Refused` with that reason. Main and S2 behave the same, so the case is a control: S2 must not change #946.
- **`s2_home_anchor_survives_log_truncation` (red baseline; D66):** nodes R (cold recipient) and holders P1, P2 and P3, ranked by agent ID. At t=0 commit C seating R, with `committed_at` = 0; the schedule drops every Put in slot 0. From t=1 s to t=20 s an admin makes 4,100 `group update` calls (name or description only, no seat change), so every node's `commit_log` drops C while C stays the anchor. At t=40 s, inside slot 1 (30–60 s), restart P2. Assert: P2 reloads C's proof from its sidecar, verifies its signature and roster root, and sends in slot 1, not on a schedule taken from its restart; P3 sends nothing before t=60 s. Then deliver R's Accepted and Receipts: every node removes the pair record and C's proof in one atomic write, and a crash during that write leaves the old or the new file whole. Negative runs: (a) before the restart a fixture removes C's proof and the pair record from P2's sidecar; P2 finds no anchor in `commit_log`, shows `anchor_unavailable` and sends nothing, while P3 still sends in slot 2 from its own proof; (b) a fixture flips one byte of C's stored signature; P2 reports `home_cert_store_unavailable` (`corrupt`) and uses no proof. Main has no scoped push or anchor store, so the case is red.

Land this ADR Proposed on main, obtain cross-model review and David's acceptance before any S2 governed code merges.
Restate 0088's acceptance order: contract, then S2 and S8(a), then S4 and S3, then S5, then S6, then S7. “S8” here means ADR 0107 S8(a); S8(b) (ADR 0114) is Accepted only after S4 as ADR 0107 requires (D65).
S2's prerequisites are the Accepted contract, red-on-main W3-H evidence, capability allocation and sidecar/wire fixtures; S2 does not wait for S5. Seal-check retirement waits for S7 after S4 is Accepted and shipped.
Use the single `named_groups.rs` code lane. D55's harness exception applies only to S8(a), never S2.

## Rulings and open questions

**Blocks David's Accept:** Q1 (the joiner's typed cause at the 120 s poll, D64) and Q2 (how a pair without an anchor proof resumes, D66).

David ruled on 2026-10-04 (D64, D65, D66, D67, D68, D96):

- **G7, L3 binds every slice (D64):** a hard rule. Every block S2 adds or touches ends in a typed refusal or a typed, visible wait that names its cause, including the 120 s join poll and upgrade or backoff waits. §6 lists them; Q1 covers the one that still needs a mechanism.
- **"S8" in the order (D65):** S8 means S8(a), ADR 0107. S8(b), ADR 0114, follows S4. S5 does not wait for ADR 0114.
- **Push timing and rounds (D66):** the recommended policy, now normative in §2. A 30 s fallback and retry slot. Shared rounds are anchored to the signed commit that triggered delivery and ranked on that commit's verified roster. Reconnect or restart never resets the anchor. Divergent views wait for reconciliation. Each node keeps every outstanding pair's anchor proof in the S2 sidecar (§5), so `commit_log` truncation cannot reset it either.
- **File cap, pruning and fairness (D67):** the recommended limits, now normative in §5. A 16 MiB cap with a retryable `capacity` answer. Pruning of departed seats only after their membership is invalidated. Fair scheduling by Home inside ADR 0089's existing budgets.
- **Joiner's own certificate on Home gossip (D68):** S5 owns its removal. S5 (ADR 0111) adds the digest-only-add rule, with its security argument and mixed-version plan, and fills the bytes by fetch-by-hash. S2 keeps the named interim exception in §2 until S5 is in effect.
- **#946 in Home (D96, against the recommendation):** keep #946 topic answers and the 10-minute refusal for legacy peers until D35's minimum supported version drops them. §7 records this as a named, ruled, time-limited exception, states its exposure, and amends ADR 0088 §2 with one named entry.

Still open for David:

- **Q1 (blocks acceptance): the joiner's typed cause at the 120 s poll (D64).**
  - **Gap.** A Home seal can wait on owner-certificate evidence for longer than the joiner's 120 s TreeKEM poll (`JOIN_RESULT_POLL_TIMEOUT`, `named_groups.rs:33213`). The joiner then ends with a `TimedOut` that names no cause. D64 needs a typed cause. Today no channel carries a non-terminal cause from the authority to the joiner.
  - **Candidate for review.** When a Home seal refuses a join attempt with `OwnerCertMemberPending`, the authority stages a signed, attempt-bound pending notice with cause `owner_certificate_pending` and the number of pending seats. It names no agent IDs, because an invite holder is not yet a member. The authority serves it on the joiner's existing join-result poll under ADR 0107's guard, only to a joiner whose current advert sets `home_owner_certificate_v1`. The joiner shows it on `/groups/:id/join-status`, and its `TimedOut` at 120 s carries that cause.
  - **Limits.** The notice is not a refusal. It grants nothing and does not extend the poll. Legacy joiners keep today's cause-free timeout (§7 residual).
  - **Shared gap.** ADRs 0110, 0112 and 0114 meet the same 120 s gap. One shared notice owned by one slice is better than four. If another slice defines it first, S2 reuses it.
  - This needs David's ruling before S2 is accepted.
- **Q2 (blocks acceptance): how a pair without an anchor proof resumes (D66).**
  - **Gap.** A node can hold an outstanding pair with no verified anchor proof. This happens when the anchor left `commit_log` before the node first ran S2, when the node caught up from a snapshot that skipped the anchor, after a downgrade spanning more than 4,096 commits, or after an operator moved a corrupt sidecar aside. §2 then sends nothing for that pair (`anchor_unavailable`). If every online holder is in that state, the push waits without a §2 reason, which L2 forbids.
  - **Proposal for review.** The node re-anchors that pair on its current verified head. It captures that head's signed commit and roster projection as the proof, persists it, and ranks from it. Every node at the same head derives the same anchor, so nodes that share a view share one schedule. A node that still holds the original proof keeps using it. Two views can overlap and cause counted duplicates, at most one sender per slot per view. They never grant authority. This departs from D66's "divergent views wait for reconciliation" only for a node that lacks history, never for a node whose view is quarantined or unverified.
  - This needs David's ruling before S2 is accepted, because it trades D66's single shared schedule for liveness.

## Follow-ups

- **Restart harness hook:** add `s2_strip_owner_certificate_from_direct_member_added` to remove O's certificate from the direct MemberAdded roster sidecar, leaving its committed digest intact, so the restart case isolates scoped persistence.
- **S2 duplicate bytes:** count the interim direct #970/#1023 sidecar bytes duplicated by Put in the size table.
- **Length:** shorten this ADR in a later editorial pass while preserving the decision, named exceptions and validation gates.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs remain byte-identical.
Record changed decisions in a successor ADR; do not edit 0007, 0038 or 0088.
