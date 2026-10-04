# ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** TBD (a cross-model review follows)
- **Slice:** Slice S5 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness)
- **Supersedes:** none. ADR 0088's supersession table assigns nothing to S5.
- **Amends:** none.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** D34(3), D54, D60, D63; ADR 0088 L1–L4, §2 item 8 and G6; [ADR 0106](./0106-join-result-carries-intervening-membership-events.md) (its deferred option 3); [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) (serving guard); [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (`EvidenceV1`); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md); [ADR 0093](./0093-capability-advert-registry.md); #811, #1023, #1143, #646, #1164, #818, #946, #970, #1025. Related work only: the join-artifact serving lifecycle note on the #1190 branch.

Two rulings used here are not in the public digest. D60 (2026-10-03): every delivery and resend of key-bearing material needs the recipient's **current** eligibility; entitlement is not fixed at the committing epoch. D63 (2026-10-04): each 0088 slice gets its own ADR, drafted Proposed and Accepted separately; S5 is ADR 0111.

## Context

ADR 0088 L1 says catch-up and repair complete when any one holder is online. Four evidence paths fall short today.

**1. Missed membership events come from one device's memory.**
- Each node logs applied TreeKEM membership events in memory only, 128 per group (`treekem_event_log`, `src/server/state.rs:1105-1107`; cap at `src/server/routes/named_groups.rs:72`). A restart loses the log.
- A member with a gap asks the peers that `admit_treekem_pending_event` names (`named_groups.rs:8796-8818`). The answer is one plain direct message with at most one event (`named_groups.rs:81`, `:10121-10142`).
- A Home `MemberAdded` is about 51.5 KB. The message limit is 49,152 B (`src/dm.rs:43`). So the page is never delivered (ADR 0106, Context point 4).
- ADR 0106 closes gaps of at most 8 from the authority's live log. Longer gaps, or an authority restart, still fail (ADR 0106, Consequences). This breaks **L1**: catch-up depends on the authority.

**2. Certificates ride per-case sidecars.**
- Seats carry only a certificate digest. The bytes ride two unsigned sidecars: on `JoinResult` (#970, `named_groups.rs:1191-1201`) and on `MemberAdded` (#1023, `named_groups.rs:1565-1583`).
- Each sidecar holds up to 32 certificates (`seat_cert_fetch.rs:665`). It is trimmed from the end until it fits the transport (`named_groups.rs:34778-34817`, `seat_cert_fetch.rs:752-791`). Trimming can drop a required certificate (the #1025 review P1).
- One certificate is about 7.25 KB in bincode (two ML-DSA-65 keys and one signature, `src/identity.rs:487-516`), or about 9.7 KB as base64. A full sidecar is about 310 KB, and the `MemberAdded` copy goes to every member.
- A missing certificate is fetched by #946: a request and an answer on the group's metadata topic (`seat_cert_fetch.rs:112-160`, `:423`). Metadata events and answers are plain JSON on that topic (`named_groups.rs:2955-2967`). Every subscriber sees the answer, not only the requester.
- Each fix so far was a per-case patch (#970, #1025, #1056, #1132). G6 stops them: S5 is the single carry rule.
- The remaining #1023 case is "every holder is offline" (`trimmed_member_added_all_holders_offline_stays_pending`, `src/server/routes/named_groups/tests/r19_cert_carry.rs:1329`). That is §2 item 8, a permitted wait. The anonymous-announce verdict (#1143) is S2.

**3. The invite carries the whole base roster.**
- A v4 invite signs the full roster projection (`src/groups/invite.rs:123-130`, `:322-323`). The cap is 20 Active+Banned entries, set by the 49,152 B command-DM wrapper (`invite.rs:201-217`). Invites stop past 20 members (#646).

**4. Private-KV history (#811) is not proven fixed.**
- KV history already moves from any holder: an empty replica asks, and any holder republishes (`src/kv/sync.rs:349-353`). Retained images are bound by an image digest (`src/kv/retained_paging.rs:1-6`).
- #811 still lacks a test with the owner and admin offline, a cold joiner, and a plain member as the only holder.

Existing parts S5 reuses:
- The control-blob pull: exact bytes, BLAKE3 digest, 8 MiB cap, chunked fetch, staged per recipient (`src/server/routes/named_groups/control_blob.rs:9-42`, `:153-200`, `:543-553`).
- The persisted roster: seat certificate bytes (`src/groups/member.rs:174`) and the `commit_log` of signed commits with roster projections, up to 4096 entries (`src/groups/mod.rs:706-722`, `:753`), both in `named_groups.json` (`src/server/mod.rs:710`).

## Decision Drivers

- L1: catch-up and repair need any one holder, never the authority, the inviter or the creator.
- L4: fetched bytes get exactly today's checks. Holders serve only currently eligible requesters (ADR 0107, D60).
- One carry rule with a fixed size bound (G6, goal E).
- No persisted authority catch-up log (D54).
- Mixed versions degrade to today's paths.

## Considered Options

1. **A persisted authority catch-up log.** Rejected by D54. It keeps catch-up dependent on the authority (L1).
2. **Raise the inline caps** (more sidecar certificates, more carried events, bigger invites). Rejected. Size grows with the roster on every message. Trimming still drops evidence. G6 stops per-case carry patches.
3. **Widen the #946 topic fetch to every object kind.** Rejected. Answers are broadcast in plain JSON to every subscriber of the metadata topic. That cannot meet L4's per-requester serving guard.
4. **Carry objects on ADR 0089 `EvidenceV1` (stream 0x06).** Rejected for object bytes. A message is at most 32 KiB, a stream carries one request, and admission is pre-identity with relationship-scoped authorization, not current group eligibility. `EvidenceV1` stays the way to find a holder's machine and KEM key after a restart.
5. **A content-addressed DHT or global store.** Rejected. Named groups are DHT-free, and a global store discloses beyond members.
6. **Direct, guarded fetch by hash from any member holder, plus an inline cap K** (chosen).

## Decision

### 1. Objects and addresses

S5 defines three content-addressed **group objects**. Each address is already bound by signed evidence the requester holds.

| Kind | Address | Holders serve from | Requester verifies, then applies through |
|---|---|---|---|
| `certificate` | BLAKE3 of bincode `AgentCertificate` (the seat digest rule, `seat_cert_fetch.rs:97-101`) | a seat's persisted `certificate`, or the holder's own identity certificate | the bytes hash to a seat digest on its committed roster; then today's hydrate checks (owner, binding; `seat_cert_fetch.rs:915`) |
| `commit_event` | `state_hash` of the event's signed `GroupStateCommit` (`src/groups/state_commit.rs:451-471`) | the new event store (§5) | the commit's `state_hash` equals the address and its signature verifies; then the ordinary metadata apply, including the #846 attested-sequence gate (`named_groups.rs:10282-10303`) |
| `roster_projection` | `roster_root` | `commit_log` entries (`RetainedCommit.roster`, `state_commit.rs:206-214`) | the projection re-derives the address; the address must equal a root in a signed commit or signed invite the requester already holds |

### 2. The single carry rule (K)

- **K = 4** (proposed). A live `MemberAdded` or `JoinResult` carries at most 4 roster certificates inline. The order stays today's (local seat first, then by agent ID). The event subject's own `certificate_b64` is not counted.
- Every other certificate is already referenced by its committed seat digest. The receiver fetches it by hash (§3). No new reference field is needed.
- The transport budget may carry fewer than K. Trimming now costs latency only, because the rest is fetchable.
- No other message carries certificates. Any future carry uses this rule (G6).
- **Sizing.** 4 × 9.7 KB ≈ 38.7 KB, against about 310 KB for today's cap of 32. The primary user has 2–5 machines (ADR 0095). In a 5-device Home the four seats other than the event's subject all fit inline, so fetch is needed only beyond 5 seats. K = 4 fits beside a Home `MemberAdded` in a control blob (8 MiB cap). An inline event keeps the 49,152 B budget and carries fewer.
- **Mixed fleet.** The published `MemberAdded` uses K only when every active seat's current verified advert sets the bit (§6). Otherwise it keeps today's sidecar. A `JoinResult` uses K only when the joiner's advert sets the bit.

### 3. Fetch protocol

- **Request:** a verified direct message `group_object_fetch_v1 { group_id, kind, digest, request_id }`, sent only to peers whose current verified advert sets the bit.
- **Answer:** one of:
  - `group_object_v1 { request_id, kind, digest, object_b64 }` inline, if it fits 49,152 B;
  - a control-blob reference of a new kind `GroupObject`, staged for that requester only and pulled through the existing chunk fetch;
  - `group_object_absent_v1 { request_id }`. It is the same for "not held" and "not eligible".
- A `GroupObject` reference is admitted only when it answers this node's outstanding request to that holder for that digest. The existing admission for other kinds is unchanged (`control_blob.rs:560-587`).
- **Holders:** any active member on the requester's committed roster, except itself. The requester asks up to 3 at once, preferring connected peers, and never waits on a named device.
- **Catch-up as control blobs (D54).** A member that holds a commit whose `prev_state_hash` it lacks fetches `commit_event` by that hash. It walks back until an event chains from its local `state_hash`, then applies forward through the ordinary apply. The walk stops on any refusal and keeps the accepted prefix, as in ADR 0106.
- A walk past the retention horizon (§5), or into a fork, adopts nothing beyond the accepted prefix. Fork and stale-base recovery stay with S3 and ADR 0064/0066; re-Welcome stays with S8 (b).
- ADR 0106's carry stays. #946 and #818 keep running beside S5 for legacy peers.

### 4. Serving guard (L4)

A holder serves an object only while **all** of these hold. It checks them at serving time, under the group membership lock, as in ADR 0107:
- the request is a verified message, the sender is the requester, and the sender is not revoked (the `control_blob.rs:595-604` pattern);
- the holder is itself an active member, and the group is neither withdrawn nor deleted (§2 item 5);
- the requester is **Active and not banned on the current committed roster**. For `OwnerCertified` groups its roster-embedded certificate verifies against the owner with the current revocation set and time, or its current verdict is `Clean`. This is ADR 0107's rule, applied per D60.
- A removed member is never eligible (§2 item 6). For Home this keeps owner-certificate disclosure to current members (D38).
- A joiner whose add is sealed is Active on every holder that applied the add, so it qualifies there. Today's #818 exception for "the target of a cached add" (`named_groups.rs:10058-10073`) is not carried over. A pre-member `roster_projection` fetch (#646) is refused until Q3 is ruled.

On a member's removal, ban or certificate revocation, its staged `GroupObject` blobs are dropped. Every chunk send re-checks eligibility. S5 never serves Welcomes or GSS key envelopes as objects; they stay on their guarded paths.

### 5. Holder store (ADR 0085)

- Certificates and roster projections are served from what each member already persists in `named_groups.json`. Nothing new is stored for them.
- **New persisted state: an event store.** Path `<data_dir>/group-holder/<stable_group_id>.bin`. Magic `X0GHS1\0\0`, then bincode `HolderStoreV1 { group_id, events: Vec<(state_hash, revision, event_json)> }`, consumed exactly.
- It holds the exact applied bytes of each commit-bearing metadata event, with the unsigned certificate sidecar removed.
- Retention per group: the newest 128 events (today's in-memory cap) and at most 16 MiB. Global cap: 256 MiB, evicting the oldest events first.
- Writes happen after the group's own persist succeeds, by temp file and rename. A failed write is logged and never blocks an apply.
- The file is deleted on local removal, ban, withdrawal or signed delete. An unknown magic or a bad body is refused, logged and left byte-identical (ADR 0085 rule 4). That group then serves nothing from the store.
- **Downgrade:** older binaries never open `group-holder/`. Upgrading again reloads it; stale entries are harmless because every object is verified by hash.
- **Not an authority log (D54):** every member keeps its own store; any member serves it; requests are by hash; nothing is decided from it.
- Fixture rule: the implementing PR adds round-trip and fail-closed tests. The first release that writes the format supplies the released fixture (ADR 0085 rule 6).

### 6. Capability bit and mixed versions

- **Bit:** `group_object_fetch_v1`, meaning "answers and sends `group_object_fetch_v1`, accepts `GroupObject` control blobs, and keeps a holder store". It is the next unallocated bit in the README registry when this ADR is Accepted (bit 3 today). It is advertised only after the holder store has loaded.
- **New to old:** an old peer never receives a request. Sidecars stay legacy-sized while any relevant advert lacks the bit or is unknown. #946 and #818 still run, so the behaviour is today's.
- **Old to new:** a new holder still answers #946 topic requests and #818 catch-up requests as today. 0.45 peers see no new message.
- Unknown capability state is not positive evidence. No request is sent until a current advert shows the bit.

### 7. Bounds (proposed)

- Requester: at most 16 outstanding fetches, at most 1 request per (digest, holder) per 30 s, one catch-up walk per group of at most 128 events and 16 MiB. An inline answer times out after 10 s; a blob pull uses the existing 115 s fetch timeout.
- Responder: the existing staging caps (4 entries and 8 MiB per peer, 64 entries, `control_blob.rs:14-20`); at most 8 requests per requester per 10 s; requests over budget are dropped without an answer.

### 8. Waits (L2, L3)

- With no eligible holder online, the fetch waits. That is §2 item 8. The state is typed and visible on the existing group diagnostics: kind, digest, since, and holders tried. It resumes when any holder comes online.
- The #946 10-minute terminal refusal stays as it is (`seat_cert_fetch.rs:55`). Whether a waiting entry may end terminally is G7.

### Security argument

- **No acceptance rule is added or relaxed.** Each fetched object gets exactly the checks it would get from gossip, #946 or #818 today. S5 changes only where the bytes come from.
- **One serving restriction is added** (§4). It narrows disclosure and widens no authority.
- A malicious holder can withhold or serve wrong bytes. Wrong bytes fail the hash or signature check, and the requester moves to the next holder. Withholding costs time only.

## Consequences

### Positive

- Catch-up and certificate repair complete from any member holder, including across authority restarts and for gaps longer than 8. This closes ADR 0106's deferred option 3.
- Sidecars shrink from about 310 KB to at most about 39 KB. Fan-out bytes per add fall in step.
- One carry rule replaces per-case patches. #646 and later slices reuse one primitive.

### Negative / Trade-offs

- A new persisted file, up to 256 MiB per node, and a new request surface with budgets.
- Large groups need a fetch round trip for certificates beyond K.
- The plain-JSON metadata topic still carries up to K certificates per add. Topic confidentiality is outside this slice.

### Neutral / Operational

- #946 and #818 stay until a later ADR retires them after a minimum supported version (D35).
- Bit allocation follows acceptance order; S3 and S6 also need bits.

## Validation

**W3-H harness cases, red before the fix (D16, D54; #1164):**
- **S5-H1, Home catch-up from a non-authority holder.** A Home TreeKEM group has owner device A and members B, C and D. D goes offline. A seals two adds. A restarts, then goes offline; B stays online. D returns. Red today: D never reaches A's head within 120 s (one-event DM pages over 49,152 B; A's log is gone). Green: D reaches the head with TreeKEM state at the head epoch, fetched from B.
- **S5-H2, long joiner gap.** A stale-invite joiner faces a 9-commit gap (over ADR 0106's cap of 8), and the authority has restarted. Red today: the joiner stays pending. Green: it converges from any member holder.
- **S5-H3, #811 exactly as asked.** In a private group, owner O and admin A write store history, and plain member P holds it. J is seated and never opens the store. O and A go offline. J opens the store cold. Assert: J has the full history within 120 s. If this is green on `main`, #811 closes as not reproduced. The case stays as a non-regression, and Q2 decides any KV change.
- **S5-H4, §2 item 8 (certificates).** An OwnerCertified Home has 7 seats. The creator is offline, and only plain member P holds its certificate. P is offline when promoted admin A2 seals a new joiner. Assert a typed wait that names the digest. P returns within the joiner's attempt. Assert the seal completes with no owner, creator or inviter online. Today this passes only through the #946 topic broadcast. That is recorded as the baseline, and the exit is the direct path with no topic answer.

**Exit tests:** H1–H4 green. Every fetched-object rejection is covered: wrong hash, bad signature, a root not bound by signed evidence, and a forked chain (#846 gate fires and adopts nothing). The holder store has round-trip, unknown-magic and truncated-body tests, with each refused file left byte-identical.

**Serving guard:** removed, banned, certificate-revoked, certificate-expired and withdrawn requesters each get `absent` and no bytes, both inline and through the blob path. A ban that races a staged blob cancels the transfer. Non-members and removed members get nothing.

**Non-regressions:** ADR 0106's carry; ADR 0107's serving guard; `trimmed_member_added_recovers_before_creator_offline_seal` and the R19 suite; KV sync tests; sidecars at most K only when every relevant advert sets the bit.

**Mixed versions:** with the released v0.46.x binary in the harness, no `group_object_*` message reaches it. Legacy sidecars, #946 and #818 behave as today in both directions. A downgrade leaves `group-holder/` untouched, and re-upgrading reloads it.

**Review triggers:** a fourth object kind; any change to K, the retention or the guard; retiring #946 or #818.

## Open questions for David

- **Q1. K.** Accept K = 4 (sized to a 5-device Home), or another value?
- **Q2. KV history (#811).** D54 rules "missed group events", not store data. Should retained KV images become a fourth object kind, fetched by their existing image digest? Or does S5 own only the #811 harness case?
- **Q3. Pre-member roster fetch (#646).** May a pending joiner fetch a `roster_projection` by presenting a signed invite that binds the root? That discloses what an invite link discloses today. Or is this decided with the W4 invite change (D13)?
- **Q4. The #946 topic answer.** Keep answering legacy requesters on the topic until the minimum supported version (D35)? Or stop earlier for D38's members-only disclosure?
- **Q5. Holder bounds.** Accept 128 events, 16 MiB per group and 256 MiB per node? A member further behind is then a matter for S3 or S8 (b).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
