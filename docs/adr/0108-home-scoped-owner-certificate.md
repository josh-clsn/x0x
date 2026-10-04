# ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD (cross-model review)
- **Slice:** Slice S2 of [ADR 0088](./0088-group-liveness-contract.md).
- **Amends, upon acceptance:** [ADR 0038](./0038-home-owner-certified-personal-space.md), the seal-time owner-certificate verdict (interim); [ADR 0007](./0007-three-layer-identity-model.md), consent for disclosure to Home members only.
- **Supersedes:** none
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D16, D38, D54, D63; [direction digest](../design/x0x-direction.md); ADR 0085, 0087, 0089, 0093, 0106, 0107; [#1143](https://github.com/saorsa-labs/x0x/issues/1143), [#1023](https://github.com/saorsa-labs/x0x/issues/1023), [#1164](https://github.com/saorsa-labs/x0x/issues/1164).

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
| The regression test requires the anonymous announce to make the seal pending. S2 reverses this expectation. | `src/server/routes/named_groups/tests/r19_cert_carry.rs:45–93` (`anonymous_announce_invalidates_hand_installed_cert`) |
| Digest-only seats remain pending until matching bytes hydrate them. Hydration does not change their commitment. | `src/groups/mod.rs:1564–1573`, `:1743–1786` |

#1023 initially asked for another certificate carry while keeping the verdict unchanged.
Its later triage separates missing bytes from #1143's false contradiction.
D54 stops per-case carry patches: S2 changes the rule; S5 owns the general carry and fetch rule.
S2 closes the false contradiction and gives Home evidence a disclosure scope.
It does not close #1023's all-holders-offline case or remove its seal-time structural dependency.
Those parts remain with S5 and S7.

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

The scope is an existing Home with its owner policy, identified by its group ID.
Use the existing Home resolution and policy predicate (`src/server/routes/home.rs:68–87`).
Do not extend implied consent to every ordinary OwnerCertified group or to another Home of the same owner.
S7 owns adoption and election changes; S2 introduces no Tier-1 kind or Home replacement.
An invite alone does not make its holder a member entitled to receive this evidence.
The joiner's existing submission of its own admission certificate stays unchanged.

### 2. Direct delivery on EvidenceV1

Propose ADR 0093 registry-v1 bit **3**, `home_owner_certificate_v1`.
It means support for both this scoped exchange and this verdict rule.
Bit 3 is unallocated in the canonical README table at this baseline.
Bit 2, `peer_evidence_v1`, proves only support for the older Hello/Lookup semantics.
Require both bits in a current verified, machine-bound advert before a scoped send.
Unknown, expired, card-only or stored capabilities do not authorize a send.
Refresh the advert through the existing route; expose missing support as retryable `recipient_upgrade_required`.
Do not probe an unknown receiver with certificate bytes.
This stricter positive gate protects disclosure; ADR 0093's existing sends keep their existing gates.
Upon acceptance, record the allocation in the canonical table and add the code constant and compatibility test; until then the bit is only proposed.

Reuse stream protocol `EvidenceV1 = 0x06`, with two new frame types:

| Type | Frozen fixed-integer bincode body |
|---|---|
| 7, `HomeCertificatePutV1` | Four `[u8; 32]` context fields in the order above, then `certificate: Vec<u8>` |
| 8, `HomeCertificateAckV1` | `accepted: bool` |

Carry the certificate's existing `to_storage_bytes()` encoding verbatim.
The receiver decodes that encoding exactly and recomputes the canonical roster digest.
Each stream carries one Put and one Ack. Types 1–6 and their bodies stay unchanged.
No announcement, advert or user key is added to this body.
Existing verified mutual agent/machine evidence must authenticate the sender and recipient agents on the live transport machines.
The pre-identity admission of EvidenceV1 alone grants no right to send or receive Home evidence.

Any active Home holder may push a committed certificate to another active member.
Push on a new committed seat, on reconnect, and when an eligible seal retry has locally held evidence to distribute.
Coalesce by context and recipient; retry at most once per 30 s per pair while eligible.
An Ack stops the current retry; restart can derive missing deliveries from the roster and local evidence.
Ack means durable evidence acceptance, never membership admission or key installation.
Sealing does not wait for all recipients to acknowledge.
This is a scoped disclosure exchange, not a new hash-fetch protocol, inline K rule or catch-up log.
S5 will supply general missing-evidence retrieval; S2 works with bytes already held locally.

### 3. Size before implementation

The fixed ML-DSA-65 sizes are 1,952 bytes per key and 3,309 bytes per signature (`src/upgrade/signature.rs:14–17`).
The three vectors add 24 bytes of lengths; issuance adds 8 bytes.
The expiry encoding and storage marker follow `src/identity.rs:766–804`.
These are calculated encoded sizes, not measured transport throughput.

| Bytes | No expiry | With expiry |
|---|---:|---:|
| Canonical certificate for roster hashing | 7,246 | 7,254 |
| Certificate storage bytes carried by Put | 7,245 | 7,258 |
| Put, including 128-byte context, 8-byte vector length, 5-byte frame and 1-byte protocol prefix | 7,387 | 7,400 |
| Put plus 6-byte Ack | **7,393** | **7,406** |

For N active seats, distributing one changed certificate to the other N−1 seats costs at most `7,406 × (N−1)` application bytes.
For N=5 that is 29,624 bytes; each receiving member gets 7,406 bytes including its Ack.
A cold new member receiving N−1 existing certificates has the same total cost.
A seal with all local bytes present and all deliveries acknowledged adds **zero** S2 wire bytes.
If a seal retry distributes q missing deliveries, its extra cost is at most `7,406 × q`; certificate verification is still per active seat.
QUIC/TLS overhead, capability refresh and existing commit/Welcome traffic are excluded.
Do not batch N certificates into a frame or repeat them in every seal.
Keep ADR 0089's 32 KiB frame cap, 5 s deadline, per-machine stream/rate limits and global budgets.
Charge Put and Ack to those budgets; use fair admission so other Homes can progress.

### 4. Verdict and L4 security argument

Use one Home-scoped evidence view for both `owner_cert_admission_failures` and `owner_cert_verdict`.
Hydrate a working roster view from verified scoped bytes before computing the verdict; newly scoped bytes persist only in the scoped file, never in legacy roster or public-cache files.
Require the bytes to match the committed seat digest; hydration must leave the roster root unchanged.
Re-check owner, subject, signature, expiry and current revocation at each use.
Use the existing verifier (`src/groups/owner_cert.rs:345–380`).

**Acceptance rule relaxed:** for this Home verdict, the canonical anonymous public digest is absence of public disclosure.
It is never a contradiction, never a warranted certificate fetch, and never starts missing-evidence grace for an otherwise valid scoped certificate.
A valid matching scoped or roster-embedded certificate yields `Clean` despite that anonymous digest.
A different certificate-bearing public digest retains today's stale-evidence handling; S2 does not decide certificate rotation policy.
Absent bytes stay pending. Invalid, wrong-owner, wrong-agent, expired or revoked evidence never becomes clean.
Ordinary groups retain their current rules.

The security argument is separation of consent scopes: anonymity says nothing about the owner's signed binding inside Home.
Transport delivery adds no authority to the certificate; the owner signature and committed digest establish it.
No signature, sender-authority, prev-hash, owner-mandate, fork, revocation or TreeKEM adoption check is relaxed.
Seals still require all active seats clean; missing evidence is not permission to seal.

Before every Put or resend, require sender, subject and recipient to be active in this Home and not banned or revoked.
Require current valid owner certificates for sender and recipient and valid current machine bindings.
Refuse withdrawn, deleted or quarantined Home state.
Linearize selection and membership invalidations under the Home membership lock.
Track and cancel in-flight disclosure before removal, ban or deletion commits; check current revocation, expiry and bindings at each transport handoff.
Use one bounded direct QUIC exchange with no hidden resend, gossip fallback or relay.
The receiver repeats these checks against its verified local committed roster; missing context is retryable and grants no evidence authority.
Keep scoped bytes out of public announces, public blob fetch, AgentCards, general EvidenceV1 Lookup and unrelated grant/trust views.
Any existing output fed by hydrated bytes must enforce this same disclosure scope; already delivered bytes cannot be recalled from a former member.
The [join-artifact lifecycle note on #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is related work on serving and egress only.
S2 does not depend on that branch, its caches or its implementation.

### 5. Persisted state and mixed versions

Use a separate `<data_dir>/home-owner-certificates.bin`, magic **`X0HCV1\0\0`**.
The frozen V1 body is a bincode vector of the four context fields plus certificate storage bytes.
Read with exact consumption; validate signatures and commitments before use, with current membership and revocation checked again at use.
Atomically persist before sending an accepted Ack; duplicate Put is idempotent.
Do not append fields to `peer-evidence.bin` or persist derived `Clean` verdicts.
Cap the file at 16 MiB and each certificate at ADR 0089's 10 KiB limit; retain current local Home seats only.
Capacity refusal stays retryable and visible; it never makes an unverified certificate usable.
Follow ADR 0085: new magic for a changed body, frozen released decoders, lazy rewrite, atomic replace and released-binary fixtures.
Unknown or corrupt formats are reported and left byte-identical; disable writes to that path until repaired.
Older binaries ignore this separate file and keep today's verdict; re-upgrade validates and reuses it.
They may still reproduce #1143. Downgrade never implies successful Home recovery.

New to old: send no scoped frames without the new bit; keep existing join/commit formats and their limitations.
Old to new: old announces and commits decode unchanged; a committed valid Home certificate survives anonymous announces under the new verdict.
New code does not infer fresh capability bits from stored evidence.
One upgraded admin with the required bytes can pass its seal gate; legacy admins retain the old refusal.
This is not a claim that every mixed-version Home converges before S5–S7.

## Consequences

- **Positive:** anonymous public identity and an offline creator no longer defeat locally held Home evidence.
- **Trade-off:** scoped persistence and guarded direct delivery add work; legacy peers and unavailable bytes retain limitations.
- **Operational:** no release date is promised from the size calculation. Scope leaks are security defects, not Home known limitations.

## Validation

All names below are required **W3-H cases to implement**, tracked by #1164; this draft claims no harness run.
Run daemon cases only in the isolated loopback-only Linux namespace; macOS fails closed.

- **`s2_home_anonymous_owner_offline` (red first):** create Home on O, admit X and A, and commit A's admin promotion. Deliver the creator's certificate to A and verify its committed digest. Ingest O's signed anonymous public announce at A, then disconnect O. Let A redeem its own valid invite for J with all other required evidence present. Before S2, assert `OwnerCertMemberPending` naming O and no completed join. After S2, assert an authoritative add, J active with usable TreeKEM keys, unchanged anonymous public output and no need for O. Rotate the creator and admin roles.
- **`s2_home_scoped_evidence_restart` (red first):** repeat the first case after restarting A with a persisted roster and creator certificate delivered by the real membership path. Re-ingest O's anonymous announce, disconnect O and redeem J's invite at A. The baseline verdict blocks despite held bytes. The fixed case must also obtain those bytes through scoped Put, persist before Ack, restart with public discovery empty and complete the same add; an injected cache is not harness evidence.
- **Exit test:** with the holder/admin reachable and no faults, both cases complete within the existing 120 s TreeKEM join window. With a lost Put/Ack, repeat after the 30 s retry and converge within that window; Ack alone never reports joined. Missing evidence exposes the seat and retry cause without reporting keyed-active.
- **Non-regressions:** flip `anonymous_announce_invalidates_hand_installed_cert` to require a clean Home verdict and successful seal; exercise both verdict sites. Keep wrong-owner, agent mismatch, signature failure, expiry, agent/machine revocation, digest mismatch, non-anonymous replacement and ordinary-group controls fail-closed. Preserve ADR 0106 carry, ADR 0107 serving guards, fork containment and TreeKEM gap exclusion.
- **Privacy/concurrency:** capture public announce, blob, Lookup and direct output. A stranger, grant-only peer, invite-only joiner or member of another Home receives no scoped bytes. Race removal, ban, withdrawal, expiry, revocation and connection replacement against each send and resend; prevent a later eligible-looking retry from releasing cancelled evidence. Validate malformed contexts, duplicate frames, oversize input, deadline and fairness limits.
- **Mixed versions/storage:** use released v0.45.0 and v0.46.0 peers in both directions, plus a peer with bit 2 only. Assert no new frame without bit 3, unchanged old decoding and documented legacy refusal. Load released fixtures, restart after lost Ack, downgrade without touching or publicly exposing the scoped file, then re-upgrade; corrupt and unknown magic remain byte-identical.
- **Boundary control:** all holders of a missing committed certificate offline stays retryable under 0088 §2 item 8; no owner bypass. S5 owns recovery when a holder returns. Invalid OwnerCertified joiners remain refused under item 2; removed epochs, signed deletion and unanchored forks keep their listed exclusions.

Harness red evidence must precede S2 code under D16/D54; D55's exception applies only to S8(a).
Land this ADR Proposed on main, obtain cross-model review and David's separate acceptance before S2 code merges.
Follow 0088's acceptance order and its single code lane for `named_groups.rs`.

## Open questions for David

- **G7 (inherited):** does L3 bind every slice, including the 120 s join poll versus the later certificate refusal, or remain a goal? S2 does not extend that timeout or settle the contract question.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs remain byte-identical.
Record changed decisions in a successor ADR; do not edit 0007, 0038 or 0088.
