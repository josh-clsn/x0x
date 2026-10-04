# ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S2 of [ADR 0088](./0088-group-liveness-contract.md).
- **Amends, upon acceptance:** [ADR 0038](./0038-home-owner-certified-personal-space.md), A Home-scoped owner certificate and a new verdict rule (interim; including the direct disclosure channel that 0038:50–51 excludes); [ADR 0007](./0007-three-layer-identity-model.md), consent for disclosure to Home members only.
- **Supersedes:** none
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D16, D38, D40, D54, D60, D63; [direction digest](../design/x0x-direction.md); ADR 0085, 0087, 0089, 0093, 0106, 0107; [#1143](https://github.com/saorsa-labs/x0x/issues/1143), [#1023](https://github.com/saorsa-labs/x0x/issues/1023), [#1164](https://github.com/saorsa-labs/x0x/issues/1164), [#1107](https://github.com/saorsa-labs/x0x/issues/1107).

Keep owner-issued certificates in a Home scope and deliver them directly to its members.
An anonymous public announce never invalidates a certificate in that scope.
Every seal still checks certificates until S7 retires those checks after S4 ships.

## Context

The promoted admin in #1143 holds the creator's certificate but cannot seal an add while the creator is offline.
The join stays pending because the creator's public announce is anonymous.
This breaks **L1**: a particular owner device must act despite an online admin holding the evidence.
It also breaks **L2**: anonymity is not on the eight-item may-block-forever list.
L3/G7 remains open; this slice preserves typed failures and makes its retry cause visible.
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

K = 1 for S2; S5 (ADR 0111) may raise K at its acceptance. The V1 vector shape is frozen now; validate its 1..K bound before accepting any entry.
Carry each certificate's existing `to_storage_bytes()` encoding verbatim.
On wire and file intake, require `to_storage_bytes(decoded) == received_certificate_bytes` and recompute the canonical roster digest.
`from_storage_bytes` uses permissive `bincode::deserialize` (`src/identity.rs:810,813`); decoding alone does not reject trailing bytes.
Each Put stream carries one Put and one Ack; a receipt-only stream carries one Receipt with no reply. Types 1–6 and their bodies stay unchanged.
No announcement, advert or user key is added to this body.
Derive each sender/recipient agent from verified current evidence binding it to the live transport machine; refuse an ambiguous binding.
The pre-identity admission of EvidenceV1 alone grants no right to send or receive Home evidence.

Ack has a frozen manual tagged encoding, not bincode's four-byte Rust enum discriminant: Accepted=0; Retry=1; Refused=2.
The reason is a typed `u8`: Retry uses context_unavailable=0, recipient_upgrade_required=1, capacity=2, persistence_failed=3, busy=4; Refused uses invalid_certificate=0, digest_mismatch=1, ineligible=2, ambiguous_binding=3, malformed=4.
Unknown tags/reasons or extra bytes are protocol errors and never acceptance.
Accepted means durable evidence acceptance, never membership admission or key installation; persist the sender's acknowledgement receipt and stop that pair's retries.
Retry sends no receipt and waits for its named condition to clear, with the proposed retry interval below; re-admit each attempt.
Refused terminates that context/recipient delivery, persists the visible terminal cause and cancels retries across reconnect/restart; a newly verified context or eligibility change may create a fresh delivery.
Timeout, lost Ack or transport failure stays unacknowledged and retries idempotently; no transport-layer automatic replay.

Use one designated pusher per context/recipient, with ordered fallback in the D40 pattern; independent all-holder pushes are forbidden.
Rank active committed seats other than the recipient by agent ID, independent of each node's discovery view. A candidate must hold verified matching bytes before it can act.
The first rank gets the first attempt; later ranks get successive fallback slots only after no acknowledged completion in earlier slots. A rank without bytes lets its slot lapse.
The recipient returns Accepted for an already-durable duplicate, then sends Receipt directly to the other N−2 candidate holders to suppress later fallback slots.
Authenticate a Receipt as coming from its named recipient on the live bound machine, require current matching Home context/membership and persist it as an Accepted receipt; a pusher cannot assert another recipient's acceptance. Gate Receipt by the same capabilities; never gossip or forward it. Lost Receipt can permit a counted duplicate in a later fallback slot.
A slot holder alone retries within its slot; a late earlier holder must wait for a new round instead of racing the current rank.
Slot timing/coordination is a proposed policy in Open questions: recommend 30 s fallback/retry with deterministic shared rounds anchored to the committed delivery trigger, not local reconnect times.
Push on new committed seats, reconnect or eligible seal retries only for unacknowledged `(context, recipient)` pairs; persist receipts in the scoped sidecar before suppressing work across restart.
Lost receipt persistence can cause duplicates in later fallback slots; Accepted is idempotent and restores the receipt. It never causes an all-holder burst.
Sealing does not wait for all recipients to acknowledge.
S5 (ADR 0111) reuses this Home push and its scope rather than starting a parallel push; it adds its general retrieval/inline-K rule without duplicate distributions. Any later retirement of this push needs an explicit successor decision.

#### Existing certificate carriers: Home egress is part of S2

| Carrier today | Home rule under S2 |
|---|---|
| #970 `JoinResult.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: serve only directly to the currently committed, authenticated recipient under ADR 0107; no public blob or gossip fallback. |
| #1023 `MemberAdded.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: retain in guarded direct member copies; drop from the gossip copy. |
| `MemberJoined` admission certificate and `MemberAdded.certificate_b64` (joiner's own certificate) | Retain on the gossiped copy as a **named interim exception** pending David's answer to ADR 0111 Q8; guarded direct copies stay unchanged. |
| #946 `GroupCertFetchResponse.cert_json_b64` | **Named interim exception** pending David's answer to ADR 0111 Q4: upgraded Home holders keep answering #946 as today, including metadata-topic answers. |

The #1023 sidecar is built at `src/server/routes/named_groups/seat_cert_fetch.rs:696–732,752–789`, attached at `named_groups.rs:14061`, and published with `certificate_b64` at `:14051,14080`; equivalent publish paths include `:19290,19298,19562,19570`.
#946 currently publishes answers at `seat_cert_fetch.rs:403–425`; its topic answers remain the named Q4 interim exception.
The joiner's own certificate is on `MemberJoined` at `named_groups.rs:33647`, published at `:33685` and re-sent at `:33482`. ADR 0028 relays that signed event unchanged, so the certificate cannot be stripped. Every receiver rejects an OwnerCertified `MemberAdded` without `certificate_b64` (`named_groups.rs:11249–11255`); dropping it would introduce a new acceptance rule. Both joiner-certificate fields therefore remain the named Q8 interim exception.
The metadata topic is plaintext and its mesh can contain non-members (`src/gossip/pubsub.rs:1203–1228`, non-member-mesh test around `:5072`); a topic subscription is not membership authentication.
Redact only the gossip projection, retaining the committed certificate digest and signed commitment; never rewrite signed bytes. Apart from the named Q8 joiner-certificate and Q4 #946 exceptions, if any nested artifact contains certificate bytes, withhold that artifact from gossip and deliver it directly under the same guard.
Audit all event, state/snapshot, recovery, blob and retransmission serializers for nested copies; apart from those named interim exceptions pending David's answers to ADR 0111 Q8 and Q4, no owner-certificate bytes may leave a Home node except to a directly authenticated member of that Home.
The joiner's existing direct submission of its own admission certificate remains unchanged.
S5's K inline certificates follow the same Home rule, subject to David's Q8 and Q4 rulings; its general carry rule cannot restore other gossip leakage.
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
Fair scheduling and the new file/retention limits remain recommendations for David, not unruled Decisions.

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
Freeze the V1 body as three ordered vectors: certificate entries (four context fields, storage-byte vector), Accepted receipts (four context fields, recipient `[u8;32]`), and terminal Refused deliveries (four context fields, recipient `[u8;32]`, typed `u8` refusal reason). Sort each by its fixed-field tuple and reject duplicates/conflicting Accepted and Refused entries. A newly verified context/eligibility change clears the obsolete refusal atomically; restart alone does not.
Use `DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()` for wire and file bodies, with bounded decoding (`src/evidence_wire.rs:45–50`); bare DefaultOptions is varint.
Require exact body consumption and canonical certificate re-encoding equality on file as on wire; validate signatures/commitments before use and membership/revocation again at use.
Persist accepted bytes before Accepted Ack, and sender receipts before durable retry suppression: temp file, fsync file, atomic rename, fsync directory (ADR 0089 §3). A write failure yields Retry(persistence_failed); duplicate Put is idempotent.
Do not append fields to `peer-evidence.bin` or persist derived `Clean` verdicts.
Retain ADR 0089's 10 KiB certificate limit; capacity pressure yields Retry(capacity), never usable unverified evidence.
A proposed 16 MiB sidecar cap and retention/pruning policy await David in Open questions.
Keep `named_groups.json` and `home-suite-groups.json` in their unchanged legacy-safe JSON formats (#451); do not place scoped bytes or new fields there. Use inert legacy-view placeholders only where required by #451's safety pattern.
Defer any first sidecar write that changes host behaviour until ADR 0094's host commit where applicable.
Follow ADR 0085: new magic for a changed body, frozen released decoders, lazy rewrite, atomic replace and released-binary fixtures.
No released binary yet writes X0HCV1: before code merges supply a golden encoder fixture plus SHA-256 and provenance; the first release writing it supplies the actual released-binary fixture, retained by every later decoder test.
Unknown or corrupt formats are reported and left byte-identical; disable writes to that path until repaired.
Older binaries ignore this separate file and keep today's verdict; re-upgrade validates and reuses it.
They may still reproduce #1143. Downgrade never implies successful Home recovery.

New to old: send no scoped frames without `home_owner_certificate_v1`; Home certificate gossip stays redacted even for a legacy receiver except for the named Q8 joiner-certificate and Q4 #946 interim exceptions; keep existing join/commit formats and their limitations.
Old to new: old announces and commits decode unchanged; a committed valid Home certificate survives anonymous announces under the new verdict.
New code does not infer fresh capability bits from stored evidence.
One upgraded admin with the required bytes can pass its seal gate; legacy admins retain the old refusal.
This is not a claim that every mixed-version Home converges before S5–S7.

## Consequences

- **Positive:** anonymous public identity and an offline creator no longer defeat locally held Home evidence.
- **Trade-off:** scoped persistence and guarded direct delivery add work; legacy peers and unavailable bytes retain limitations.
- **Operational:** no release date is promised from the size calculation. Outside the named Q8 joiner-certificate and Q4 #946 interim exceptions, scope leaks are security defects, not Home known limitations.

## Validation

The W3-H harness (#1164) does not exist yet; these are specified cases, not claimed runs. Recommend a dedicated S2 tracking issue linked to #1164.
Each red case must be committed and shown red on main before S2 code merges; in-process red tests alone do not satisfy D16/D54.
Run daemon cases only in the isolated loopback-only Linux namespace; macOS fails closed.
All cases use a deterministic clock t=0, public create/admit/promote/invite/redeem APIs, and a scheduled transport that records every write; advance time only at the named barriers. Fixtures prepare signed metadata/capabilities, never inject discovered certificate bytes.

- **`s2_home_anonymous_owner_offline` (red baseline):** nodes O (creator), X (holder), A (promoted admin), J (joiner). At t=0 create Home O, admit X/A and commit A's promotion; deliver O's certificate through the actual member path and verify its digest on A. At t=1 O emits a machine-signed anonymous announce; deliver it to A, then disconnect O. At t=2 redeem J's valid A-issued invite with other evidence already present. Main returns OwnerCertMemberPending for O; S2 completes the authoritative add and J's Welcome/key installation without O. Anonymous public output stays unchanged. Repeat with creator/admin identities permuted.
- **`s2_home_scoped_evidence_restart` (red baseline, store isolation):** same nodes; at t=0 drive the trimmed-sidecar shape of `trimmed_member_added_all_holders_offline_stays_pending` (`r19_cert_carry.rs:1329`), but keep X online with O's bytes. A is seated/promoted from a real trimmed MemberAdded and has only O's committed digest; no JoinResult, #946 answer or discovery entry may supply O's bytes. At t=1 X establishes the authenticated binding and sends the real scoped Put; A persists it before Accepted, then disconnect O/X and restart A at t=2 with empty discovery and unchanged digest-only legacy roster. At t=3 redeem J's invite and seal using only the new sidecar as O's byte source. Main remains pending/no scoped durable recovery; S2 seals and installs J's keys. Delete/disable only the new sidecar in a negative run and require pending again. Avoid ADR 0070 owner-trust APIs; #1107 is excluded. Keep the old membership-carried restart shape as a separate red verdict reproduction, not evidence for the new store.
- **`s2_home_ordinary_group_twin` (control + red):** nodes A/J, clock t=0; create the ordinary PublicRequestSecure + OwnerCertified shape via APIs. Preserve `anonymous_announce_invalidates_hand_installed_cert` as the fail-closed ordinary-group control. At t=1 deliver A's own signed anonymous announce; its seal stays pending on main and S2. Repeat with committed Home metadata/policy: only that twin changes from red/pending to Clean and successful seal. Exercise both production verdict sites and assert real-roster grace stamps survive evaluations/restart.
- **`s2_home_all_egress_privacy` (red baseline):** O/X/A plus stranger S, grant-only G, invite-only J and other-Home H; t=0 create the memberships and attach S to the non-member topic mesh. At t=1 drive each #970, #1023, MemberJoined admission certificate (publish and resend), MemberAdded.certificate_b64 and #946 carrier, the ADR 0028 unchanged MemberJoined relay, all gossip publish/recovery/blob paths, and Put. Capture EVERY egress, including publishes before mesh delivery, and decode nested JSON/base64/bincode/storage encodings. Search every byte string/candidate certificate for a canonical digest equal to ANY Home member certificate, including locally held/embedded bytes rather than only the new store. Main leaks to the topic; S2 explicitly permits only the joiner's own certificate on gossiped MemberJoined (including its unchanged ADR 0028 relay) and MemberAdded.certificate_b64 under the named Q8 interim exception, plus today's #946 answers under the named Q4 interim exception. Assert those exceptions explicitly; every other certificate egress on gossip is forbidden and certificate bytes otherwise leave only on bound direct member channels. At t=2 race removal/ban/withdrawal/expiry/agent-machine-binding revocation/verdict/quarantine and connection replacement with writes; no subsequent cancelled send/resend may leak. K paths also require the current epoch. Record public announces/cards/Lookup unchanged.
- **`s2_home_designated_push_and_ack` (control for counts, red for new protocol):** five active nodes, t=0 commit one shared delivery trigger and freeze candidate ranks; all hold the same certificate. Deliver first-rank traffic before fallback and require four Puts, 29,656 Put/Ack bytes plus 1,992 Receipt bytes, total 31,648 application bytes; deliver/persist all receipts before later slots. Give a cold recipient four existing certificates and require four Puts, not sixteen. Restart all nodes after fsync'd Accepted receipts: zero certificate re-push. Delay or drop Receipt and assert only the named recipient can authorize retry suppression; count the resulting fallback duplicates. In separate schedules lose Put, Ack or receipt fsync; advance the proposed shared fallback clock by 30 s, admit only the scheduled rank, and count every duplicate. Exercise each typed Retry/Refused reason: condition-cleared retry, terminal cancellation, no receipt on failure and no false membership confirmation. Two digest-only nodes exchange self-subject Puts through authenticated bindings without a mutual-cert deadlock; the exception never releases K/join artifacts.
- **Exit/non-regressions (controls):** with one holder/admin reachable and no faults, complete each Home add within the existing 120 s TreeKEM window; loss/fallback scenarios use the proposed schedule and expose typed waits. Preserve ADR 0106 carry and ADR 0107 serving guards. Keep wrong-owner/agent, signature, expiry, revocation, commitment mismatch, non-anonymous replacement, fork/TreeKEM-adoption exclusions and ordinary groups fail-closed. All holders offline remains retryable under 0088 §2 item 8; return one holder and resume without owner bypass. Cover malformed/duplicate/oversize frames, canonical re-encoding, trailing bytes, deadlines, budgets and fairness.
- **Mixed versions/storage (controls):** at t=0 pair candidate with released v0.45.0/v0.46.0 in both directions and a peer advertising only `peer_evidence_v1`; no new frame without `home_owner_certificate_v1`, no certificate-bearing Home gossip fallback outside the named Q8 joiner-certificate and Q4 #946 interim exceptions, legacy verdict limitations visible. After t=1 accepted Put/fsync, crash before/after file rename, directory fsync and Ack; restart with empty discovery, lose Ack, downgrade, then re-upgrade. Old binaries start on unchanged legacy JSON and leave `.hscert` byte-identical; unknown/corrupt magic stays intact with writes disabled. Load golden and, once available, first-released X0HCV1 fixtures with SHA-256 checks.

Land this ADR Proposed on main, obtain cross-model review and David's acceptance before any S2 governed code merges.
Restate 0088's acceptance order: contract, then S2 and S8(a), then S4 and S3, then S5, then S6, then S7. “S8” here means ADR 0107 S8(a); S8(b) is Accepted only after S4 as ADR 0107 requires.
S2's prerequisites are the Accepted contract, red-on-main W3-H evidence, capability allocation and sidecar/wire fixtures; S2 does not wait for S5. Seal-check retirement waits for S7 after S4 is Accepted and shipped.
Use the single `named_groups.rs` code lane. D55's harness exception applies only to S8(a), never S2.

## Open questions for David

- **G7 (inherited):** does L3 bind every slice, including the 120 s join poll versus later certificate refusal, or remain a goal? S2 does not extend that timeout.
- **Push coordination/bounds (recommendation):** accept a 30 s fallback/retry slot? Recommend shared rounds anchored to the signed committed delivery trigger timestamp, using the same verified committed roster for ranks; reconnect/restart must not reset the anchor. Divergent/quarantined views wait for verified reconciliation instead of inventing a local rank. Before acceptance settle the round policy and any persisted coordination fields; if fields are needed, freeze them in V1 before its first release. This recommendation is not yet a ruled timeout Decision; Receipt frame/receipt persistence and their costs are specified above.
- **Capacity/retention/fairness (recommendation):** accept a 16 MiB sidecar cap, prune certificates/receipts for departed Home seats only after membership invalidation, and schedule fairly by Home within ADR 0089's existing budgets? New rates, limits and retention remain proposals until ruled.

## Follow-ups

- **Restart harness hook:** add `s2_strip_owner_certificate_from_direct_member_added` to remove O's certificate from the direct MemberAdded roster sidecar, leaving its committed digest intact, so the restart case isolates scoped persistence.
- **Moving bindings:** change `Refused(ambiguous_binding)` to `Retry(ambiguous_binding)` before the V1 encoding freezes; bindings move under ADR 0089.
- **S2 duplicate bytes:** count the interim direct #970/#1023 sidecar bytes duplicated by Put in the size table.
- **Length:** shorten this ADR in a later editorial pass while preserving the decision, named exceptions and validation gates.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs remain byte-identical.
Record changed decisions in a successor ADR; do not edit 0007, 0038 or 0088.
