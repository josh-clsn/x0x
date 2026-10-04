# ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review, r1 REQUEST-CHANGES addressed in r2); further review TBD
- **Slice:** Slice S5 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness)
- **Supersedes:** none. ADR 0088's supersession table assigns nothing to S5.
- **Amends:** none.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** D34(3), D54, D60, D63; ADR 0088 L1–L4, §2 items 4–8, G6, G7; [ADR 0106](./0106-join-result-carries-intervening-membership-events.md) (its deferred option 3); [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) (serving guard); [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (`EvidenceV1`); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md); [ADR 0093](./0093-capability-advert-registry.md); [ADR 0087](./0087-repository-and-release-governance.md) rule 8; #811, #1023, #1143, #646, #1164, #818, #946, #970, #1025. Related work only: the join-artifact serving lifecycle note on the #1190 branch.

Two rulings used here are not in the public digest. D60 (2026-10-03): every delivery and resend of key-bearing material needs the recipient's **current** eligibility; entitlement is not fixed at the committing epoch. D63 (2026-10-04): each 0088 slice gets its own ADR, drafted Proposed and Accepted separately; S5 is ADR 0111.

**Gates.**
- **Acceptance order** (0088 §4): the contract, then S2 and S8, then S4 and S3, then S5. S5 is Accepted only after S2 (0108), S4 (0110) and S3 (0109) are Accepted. S8 (a) is ADR 0107, already Accepted. S8 (b) (0114) is filed after S4 (ADR 0107); S5 does not depend on it (Q7).
- **Merge:** this ADR lands Proposed on `main` before any code it governs merges to any branch. David Accepts it before S5's implementation merges to `main` (0088 §4, ADR 0087 rule 8).
- **Harness first** (D16, D54): every red case in Validation is committed to W3-H and shown red on `main` before S5's code merges. No exception applies.
- **One lane:** S5 code that touches `named_groups.rs` takes the single lane (0088 §4).
- **Q5 gate:** S5 is not Accepted until David answers Q5. Until then the holder-only liveness gap in Consequences stays.

## Context

ADR 0088 L1 says catch-up and repair complete when any one holder is online. Four evidence paths fall short today.

**1. Missed membership events come from the author's memory.**
- Each node logs applied TreeKEM membership events in memory only, 128 per group (`treekem_event_log`, `src/server/state.rs:1105-1107`; cap at `src/server/routes/named_groups.rs:72`). A restart loses the log.
- A member with a gap asks the peers that `admit_treekem_pending_event` names (`named_groups.rs:8796-8818`). The answer is one plain direct message with at most one event (`named_groups.rs:81`, `:10121-10142`). A Home `MemberAdded` is about 51.5 KB, over the 49,152 B limit (`src/dm.rs:43`), so the page is never delivered (ADR 0106, Context point 4).
- Even a delivered page fails when the holder did not author the event. The apply requires `actor == sender` (`named_groups.rs:11300-11303`). The signed `GroupStateCommit` covers the state fields, not the whole event (`src/groups/state_commit.rs:476-496`). So only the author can serve its events.
- ADR 0106 closes gaps of at most 8 from the authority's live log. Longer gaps, or an authority restart, still fail. This breaks **L1**: catch-up depends on the author.

**2. Certificates ride per-case sidecars.**
- Seats carry a certificate digest. The bytes ride two unsigned sidecars: on `JoinResult` (#970, `named_groups.rs:1191-1201`) and on `MemberAdded` (#1023, `named_groups.rs:1565-1583`). Each holds up to 32 (`seat_cert_fetch.rs:665`) and is trimmed from the end to fit (`named_groups.rs:34778-34817`, `seat_cert_fetch.rs:752-791`). Trimming can drop a required certificate (the #1025 review P1).
- One certificate is about 7.25 KB in bincode (`src/identity.rs:487-516`), about 9.7 KB as base64. A full sidecar is about 310 KB, sent to every member.
- A missing certificate is fetched by #946 on the group's metadata topic (`seat_cert_fetch.rs:112-160`, `:423`). Metadata traffic is plain JSON (`named_groups.rs:2955-2967`), so every subscriber sees the answer. The topic mesh can include non-members (`src/gossip/pubsub.rs:1203-1228`; the non-member mesh test at `:5072`), so today's Home sidecars and answers reach peers that D38 excludes.
- After 10 minutes #946 stages a terminal `certificate_evidence_unavailable` refusal (`seat_cert_fetch.rs:55`, `named_groups.rs:33905-33925`). §2 item 8 says such a fetch waits until a holder is online.
- Each fix so far was a per-case patch (#970, #1025, #1056, #1132). G6 stops them. The remaining #1023 case is "every holder offline" (`r19_cert_carry.rs:1329`), which is §2 item 8. The verdict defect (#1143) is S2.

**3. The invite carries the whole base roster.** A v4 invite signs the full projection (`src/groups/invite.rs:123-130`, `:322-323`). It is capped at 20 Active+Banned entries by the command-DM wrapper (`invite.rs:201-217`), so invites stop past 20 members (#646).

**4. Private-KV history (#811) is not proven fixed.** KV history already moves from any holder (`src/kv/sync.rs:349-353`; image digests, `src/kv/retained_paging.rs:1-6`). #811 still lacks its test.

S5 reuses the control-blob pull (exact bytes, BLAKE3, 8 MiB, per-recipient staging; `control_blob.rs:9-42`, `:153-200`, `:543-553`). It also reuses what members already persist in `named_groups.json` (`src/server/mod.rs:710`): seat certificates (`src/groups/member.rs:174`) and the `commit_log` of signed commits with projections (`src/groups/mod.rs:706-722`).

## Decision Drivers

- L1: catch-up and repair need any one holder, never the author, inviter or creator.
- L4: every fetched byte is authenticated by signed evidence. Holders serve only currently eligible requesters (ADR 0107, D60).
- One carry rule with a fixed size bound (G6, goal E).
- No persisted authority catch-up log (D54).
- Mixed versions degrade to today's paths.

## Considered Options

1. **A persisted authority catch-up log.** Rejected by D54. Catch-up stays dependent on the authority (L1).
2. **Raise the inline caps.** Rejected. Size grows with the roster on every message, trimming still drops evidence, and G6 stops per-case carries.
3. **Widen the #946 topic fetch to every kind.** Rejected. Answers are broadcast in plain JSON to every subscriber, so no per-requester guard is possible.
4. **Use ADR 0089 `EvidenceV1` (stream 0x06) as the carrier.** Rejected for object bytes: a 32 KiB message cap, one request per stream, and pre-identity admission under relationship scope, not group eligibility. It stays the way to find a holder's machine and KEM key after a restart.
5. **Re-verify relayed events from the gossip envelope.** Rejected. It ties evidence to saorsa-gossip internals, and events delivered by direct message have no reusable envelope.
6. **A DHT or global store.** Rejected. Named groups are DHT-free, and a global store discloses beyond members.
7. **Author-signed event evidence, a guarded direct fetch by hash from any member holder, and an inline cap K** (chosen).

## Decision

### 1. Objects and the evidence that authenticates them

| Kind | Address | Bytes served | Requester accepts only when |
|---|---|---|---|
| `certificate` | BLAKE3 of bincode `AgentCertificate` (`seat_cert_fetch.rs:97-101`) | the whole certificate | it hashes to a seat digest on the requester's committed roster; then today's hydrate checks (`seat_cert_fetch.rs:915`) |
| `commit_event` | the commit's `state_hash` | the canonical event with its `author_evidence` (§2) | the author evidence and the commit signature verify, and the commit's `state_hash` equals the address; then the apply in §2 |
| `roster_projection` | `roster_root` | only the root-covered fields: agent ID, role, state and certificate digest | they re-derive the address (`state_commit.rs:183-196`), and the address equals a root in a signed commit the requester holds |

A fetched projection never carries `treekem_key_package_hash`. The root does not cover it (`state_commit.rs:110-114`, `:138-147`). A consumer that needs it takes it from evidence that covers it: the add commit's `security_binding`, or a signed invite view.

### 2. Author evidence and the fetched-event apply

- **Minting.** When a capable authority seals a commit-bearing metadata event, it adds an optional field `author_evidence { signer_public_key, signature }`. The field is serde-default and omitted when absent, as in ADR 0106. The signature is ML-DSA-65 over `x0x/group-event-evidence-v1\0 ‖ group_id ‖ state_hash ‖ event_digest`, with length prefixes.
- **Digest (RFC 8785 JCS).** `event_digest` is the BLAKE3 of the JCS bytes of the event value, after the top-level members `author_evidence` and `roster_certificates_b64` are removed.
  - **Parse once.** The receiver parses the received bytes once into a JSON value. The parser rejects duplicate keys at any depth, invalid UTF-8 and lone surrogates. Verification and apply consume that one value: the event is deserialized from it and never re-parsed from the bytes.
  - **Bytes.** Object keys are sorted by UTF-16 code units at every depth. Arrays keep their order. There is no whitespace. A string escapes only `"`, `\` and U+0000–U+001F (as `\b`, `\f`, `\n`, `\r`, `\t` or lowercase `\u00xx`). Every other character is literal UTF-8.
  - **Numbers.** Every number must be an integer with magnitude at most 2^53 − 1, written in plain decimal (I-JSON). Any other number makes the evidence invalid: the authority does not mint it, and the receiver falls back to the legacy author-only rule.
  - **Coverage.** Every other member is covered, including members a newer version adds.
  - **Minting.** The authority serializes the event, parses its own output with the same parser, and signs the digest of that value.
- **Signer.** It must be the commit's signer: `signer_public_key` and `committed_by`.
- **Budget.** The evidence never moves an event onto a transport that a legacy receiver may not support (#970's rule). If it would, it is omitted, and that event stays servable only by its author.
- **Apply.** A fetched event is applied through the ordinary metadata apply with an explicit origin `Fetched { author, holder }`. Every check that compares the transport sender (for example `actor == sender`) compares the verified author. The holder is never treated as the sender. All other checks run unchanged: the actor's current role, revocation, prev-hash linkage, owner mandate, TreeKEM rules and the #846 gate (`named_groups.rs:10282-10303`).
- **Not a carry.** A fetched event never satisfies a bound join-attempt rule, and it is never re-published.
- **Legacy events.** An event without evidence is accepted from a holder only when the holder is its author, which is today's rule.

### 3. The single carry rule (K)

- **K = 4** (proposed). A live `MemberAdded` or `JoinResult` carries at most 4 certificates inline, in today's order (local seat first, then by agent ID). The event subject's own `certificate_b64` is not counted.
- Every other certificate is already named by its committed seat digest, and is fetched by hash. No new reference field is needed. Trimming now costs latency only.
- No other message carries certificates. Any future carry uses this rule (G6).
- **Home groups (D38).** D38 discloses a Home owner's certificate only to that Home's members. The metadata topic is plaintext gossip whose mesh can include non-members (Context, item 2). So in Home groups:
  - the gossiped `MemberAdded` carries no roster sidecar, whatever the adverts say, and the `JoinResult` carries none either;
  - certificates leave a node only on direct, member-authenticated channels: S5's fetch by hash (§4, under §5's guard) or S2's direct Put;
  - **S5 reuses S2's direct Put** as the Home push half of this rule. It does not retire it, and it is not a second carry rule. Under S5 a Put carries at most K certificates, goes only to a recipient that passes §5's guard, and uses §5's single admitted exchange;
  - the subject's own `certificate_b64` on the gossiped Home `MemberAdded` also reaches the mesh. Receivers require it today (`named_groups.rs:11249-11255`), so S5 cannot drop it without a new acceptance rule (Q8).
- **Ordinary groups:** K inline on the gossiped copy stays.
- **Sizing.** 4 × 9.7 KB ≈ 38.7 KB, against about 310 KB today. The primary user has 2–5 machines (ADR 0095). With K = 4, one ordinary event, or one S2 Put in a Home, covers every other seat of a 5-seat group.
- **Mixed fleet (ordinary groups).** The published `MemberAdded` uses K only when every active seat's current verified advert sets the bit. A `JoinResult` uses K only when the joiner's advert does. Otherwise today's sidecar stays.

### 4. Fetch, head discovery and catch-up

- **Request:** a verified direct message `group_object_fetch_v1 { group_id, kind, digest, request_id }`. **Head query:** `group_head_v1 { group_id, request_id }`. The holder answers a head query with its latest committed event as a `commit_event` object.
- Requests go only to peers whose current verified advert sets the bit.
- **Answer:** the object inline when it fits 49,152 B; otherwise a control-blob reference of a new kind `GroupObject`, staged for that requester only. Otherwise `group_object_absent_v1 { request_id }`, which is the same for "not held" and "not eligible". A `GroupObject` reference is admitted only when it answers this node's outstanding request to that holder.
- **Holders:** any active member on the requester's committed roster, except itself. The requester asks several at once and never waits on a named device.
- **Head discovery triggers:** daemon start; each new connection to an active member; any received event with a gap (today's #818 trigger); and a periodic probe (Q6). A stale head from one holder only delays convergence. A forked head goes to the existing fork handling.
- **Catch-up as control blobs (D54).** From a verified head newer than its own, the member fetches `commit_event` by each `prev_state_hash` in turn, until it reaches an event that chains from its local `state_hash`. It then applies forward (§2). The walk stops at the first refusal and keeps the accepted prefix, as in ADR 0106.
- ADR 0106's carry stays. #946 and #818 keep running beside S5 for legacy peers.

### 5. Serving guard (L4)

A holder serves an object only while **all** of these hold:
- the request is verified, the sender is the requester, and the sender is not revoked (`control_blob.rs:595-604`);
- the holder is an active member, and the group is not withdrawn, deleted (§2 item 5) or fork-quarantined (ADR 0064/0066; ADR 0107 §Decision);
- the requester is **Active and not banned on the current committed roster**, with ADR 0107's certificate rule for `OwnerCertified` groups: the roster-embedded certificate with the current revocation set and time, or a current `Clean` verdict. A removed member is never eligible (§2 item 6). Home disclosure therefore stays with current members (D38).
- A joiner whose add is sealed is Active on every holder that applied it. Today's #818 "target of a cached add" exception (`named_groups.rs:10058-10073`) is not carried over. A pre-member `roster_projection` request (#646) is refused until Q3 is ruled.

**Every physical exchange is admitted afresh.** That covers each inline answer, each chunk and each retry. Admission runs right before the transport write, in one single-exchange send with no transport-level resend. Each retry is a new request, admitted again.
- Today the chunk path copies the bytes and only then spawns the send (`control_blob.rs:633-657`). So the S5 chunk task re-admits inside the task.
- Object bytes never use gossip or the gossip-capable direct-message fallback.
- On removal, ban, revocation, certificate expiry, a verdict change, withdrawal, deletion, local leave or quarantine, the holder aborts and awaits that requester's in-flight S5 sends, then purges its staged copies.
- These are the class-R properties of the #1190 lifecycle note (related work). S5 requires the properties; it does not depend on that branch merging.
- S5 never serves Welcomes or class-K key envelopes. D60's epoch-bound share admission stays the separate guard for them.

### 6. Holder store (ADR 0085)

- Certificates and projections are served from `named_groups.json`. Nothing new is stored for them.
- **New persisted state:** one file per event, `<data_dir>/group-holder/<stable_group_id>/<state_hash>.ev`. Each file is magic `X0GHE1\0\0`, then bincode `HeldEventV1 { revision, committed: bool, event_json }`, consumed exactly. `event_json` is the JCS bytes (§2) of the event value with only `roster_certificates_b64` removed.
- **Order and durability.**
  - Before persisting the roster for a sealed or applied commit, the node writes the event's file with `committed = false`: a temp file, fsync, rename, then fsync of the directory.
  - After the roster persist succeeds, it rewrites the file with `committed = true` by the same method.
  - On restart it reconciles: a file whose `state_hash` is on the committed chain (`commit_log` or head) becomes committed. Any other file is deleted.
  - An uncommitted file is never served. A crashed seal therefore cannot leak a commit that might be replaced at the same revision.
- **Failure:** a failed write is logged and never blocks the commit; coverage drops by one event. An unknown magic or a bad body is refused, logged and left byte-identical (ADR 0085 rule 4).
- **Deletion:** the group's directory is deleted on local removal, ban, withdrawal or signed delete.
- **Downgrade:** older binaries never open `group-holder/`. Upgrading again reconciles it.
- **Not an authority log (D54):** every member keeps its own copy; any member serves it; requests are by hash; nothing is decided from it.
- **Retention:** bounded. The values are recommendations pending Q5 and Q6, not part of this decision.
- The implementing PR adds round-trip, fail-closed and crash-point tests. The first release that writes the format supplies the released fixture (ADR 0085 rule 6).

### 7. Capability bit and mixed versions

- **Bit:** `group_object_fetch_v1`: "answers and sends S5 requests, mints and verifies `author_evidence`, accepts `GroupObject` blobs, keeps a holder store". It is named here. Its number is the next unallocated bit when this ADR is Accepted. It is advertised only after the holder store has reconciled.
- **New to old:** old peers never receive S5 requests. In ordinary groups, sidecars stay legacy-sized while a relevant advert lacks the bit or is unknown. In Home groups the gossiped sidecar is gone for every member (D38); an old Home member recovers certificates through S2's Put or #946 (Q4). Old receivers ignore `author_evidence`. #946 and #818 still run.
- **Old to new:** a new holder answers #946 and #818 as today. Legacy events stay author-served. 0.45 peers see no new message.
- Unknown capability state is not positive evidence. Requests wait for a current advert that shows the bit.

### 8. Waits (L2, L3)

- With no eligible holder online, a fetch waits (§2 item 8). It stays retryable across join-attempt deadlines and resumes when any holder comes online.
- The state is typed and visible: kind, digest, since, and holders tried.
- For a requester that advertises the bit, the authority does not stage the #946 terminal refusal while an S5 fetch for that digest is pending. It reports a typed, retryable `evidence_pending` status instead.
- **Legacy behaviour, named separately:** toward peers without the bit, #946 keeps its 10-minute terminal refusal. That conflicts with §2 item 8. Retiring it belongs to Q4.
- G7 (whether L3 binds every slice, and the joiner's 120 s poll) stays open. S5 relies on G7 for nothing.

### 9. Security argument (L4)

- **One acceptance rule changes. Authorship of a fetched commit-bearing event may be proven by a detached author signature over its canonical digest (§2), instead of by the transport sender.**
  - That signature is the same ML-DSA-65 key over the complete security-relevant content, so it is at least as strong as sender authentication of the same bytes.
  - A replay applies only at its own place in the chain (prev-hash linkage).
  - The author's current authority and revocation are still checked at apply time. The holder gains no authority.
- **Every other fetched object has today's checks.** A certificate or projection is accepted only when it hashes to a value bound by a signed commit. Hash-uncovered fields are never accepted (§1).
- **One serving restriction is added** (§5). It narrows disclosure.
- A malicious holder can withhold or serve wrong bytes. Wrong bytes fail verification, and the requester tries another holder. Withholding costs time only.

## Consequences

### Positive

- Catch-up and certificate repair complete from any member holder, across author restarts and for gaps longer than 8. This closes ADR 0106's deferred option 3.
- Sidecars shrink from about 310 KB to at most about 39 KB.
- One carry rule replaces per-case patches. #646 and later slices reuse one primitive.

### Negative / Trade-offs

- One extra ML-DSA-65 signature per commit (about 4.4 KB as base64) and one verify per fetched event.
- A new persisted directory with two writes per commit, and a new request surface.
- Events sealed by legacy authorities stay author-served.
- A member that falls behind every holder's retention has no holder-only exit (Q5).
- In ordinary groups the metadata topic still carries up to K certificates per add, in plain JSON.
- In Home groups the subject's own `certificate_b64` (Q8) and legacy #946 answers (Q4) still reach the gossip mesh until ruled. Old Home members lose the inline sidecar.

### Neutral / Operational

- #946 and #818 stay until a later ADR retires them (D35).
- The bit number follows acceptance order. S3 and S6 also need bits.

## Validation

W3-H (#1164) does not exist yet. Each case below is a specification: nodes, steps, assertion and baseline. **Gate:** each red case is committed and shown red on `main` before S5's code merges. The run is recorded on the implementing PR.

**Red cases (must be red on `main`):**
- **H1, Home catch-up from a non-author holder.**
  - Nodes: owner device A (authority), admin B, plain member C, member D, joiners E and F.
  - Steps:
    1. A, B, C and D converge on a Home TreeKEM group.
    2. D stops.
    3. A seals the adds of E and F.
    4. A restarts, then stops.
    5. D starts.
    6. (a) No further event is sent. (b) B seals one more add.
  - Assert: within 120 s D's state hash and TreeKEM epoch equal C's, and D decrypts a message C sends.
  - Baseline on `main`: red. In (a) D is never told the head. In (b) the #818 page from B fails `actor == sender`.
- **H2, long joiner gap.**
  - Nodes: authority A, devices K1–K9, joiner J.
  - Steps:
    1. A mints J's invite.
    2. A seals the adds of K1–K9.
    3. A restarts.
    4. J redeems the invite. A seals J's add and delivers the result.
    5. A stops.
  - Assert: within 120 s J is Active with TreeKEM installed, fetched from the K devices.
  - Baseline on `main`: red. The 9-event gap is over ADR 0106's cap, and A's log is gone.
- **H3, §2 item 8 resumes.**
  - Nodes: an OwnerCertified Home of 7 seats. Owner device O is the creator. A2 is a promoted admin. P is a plain member. J is a capable joiner.
  - Setup: the harness makes A2's seat for O digest-only.
  - Steps:
    1. O and P stop.
    2. J redeems at A2, and A2 attempts to seal.
    3. At minute 12, P starts, and J retries.
  - Assert: before minute 12, A2 reports a typed retryable wait naming O's digest, and no terminal refusal. Within 60 s of P's start, A2 holds O's certificate. The seal completes on J's retry.
  - Baseline on `main`: red. The terminal refusal fires at 10 minutes.

**Controls (expected green on `main`; they must stay green):**
- **C1, certificate from an online plain holder.** As H3, but P stays online. Baseline: green through the #946 topic answer. **Exit:** green with zero #946 topic answers from P (the "group-scoped certificate answer sent" counter), and the certificate delivered by the S5 direct path.
- **C2, #811 exactly as asked.**
  - Steps: in a private group, owner O and admin A write store history, and plain member P holds it. J is seated and never opens the store. O and A stop. J opens the store cold.
  - Assert: J reads the full history within 120 s.
  - Baseline: run first. If it is red, Q2 decides whether S5 owns the fix. If it is green, #811 closes as not reproduced.

**Exit tests:** H1–H3 green; C1 and C2 unchanged or better.
- Rejections: wrong hash; bad author or commit signature; a mismatched signer; a projection carrying an uncovered field; a root no signed commit binds; a forked chain (the #846 gate fires); a legacy event from a non-author holder.
- **Digest test vectors** (committed with the implementation, each with its expected BLAKE3):
  - nested objects whose keys sort differently by UTF-16 code unit and by code point (for example U+E000 against U+1F600);
  - integers 0 and 2^53 − 1 accepted; 2^53, `1.0` and `1e3` make the evidence invalid;
  - non-ASCII text given literally and as `\u` escapes yields one digest; U+001F becomes `\u001f`;
  - whitespace variants of one value yield one digest;
  - a duplicate key, at the top level and nested, is rejected;
  - an unknown member is retained and covered, so changing it fails verification;
  - changing `roster_certificates_b64` or `author_evidence` does not change the digest.
- **Home disclosure:** a non-member peer in a Home's metadata mesh receives no roster-sidecar certificate and no S5 answer from a capable node. Members still converge through S5 fetch or S2's Put.
- Store crash points: before the uncommitted write, between it and the roster persist, and between the persist and the committed write. After each, committed events are servable and uncommitted ones are never served. Unknown-magic and truncated files are left byte-identical.

**Serving guard:** removed, banned, revoked, expired, verdict-changed, withdrawn and quarantined cases each get `absent` and no bytes, inline and by chunk. An invalidation that races an in-flight chunk aborts it before its write. A retry is admitted afresh.

**Non-regressions:** ADR 0106's carry; ADR 0107's guard; the R19 suite; KV sync tests; D60 share admission unchanged.

**Mixed versions:** with the released v0.46.x binary in the harness, no S5 message reaches it. Legacy sidecars, #946 and #818 behave as today in both directions. Old receivers apply events that carry `author_evidence`. A downgrade leaves `group-holder/` untouched.

## Open questions for David

- **Q1. K.** Accept K = 4, sized so one event or one S2 Put covers a 5-seat group?
- **Q2. KV history (#811).** D54 rules on "missed group events", not store data. If C2 is red, should retained KV images become a fourth kind, fetched by their image digest?
- **Q3. Pre-member roster fetch (#646).** May a pending joiner fetch a projection by presenting a signed invite that binds its root? That discloses what an invite link discloses today. Or is this decided with the W4 invite change (D13)?
- **Q4. #946 retirement.** Keep the topic answer and its 10-minute terminal refusal for legacy peers until the minimum supported version (D35), or retire them sooner for §2 item 8 and D38? In Home groups a topic answer reaches non-member mesh peers.
- **Q5. Retention exhaustion (L1).** A member behind every holder's retention cannot catch up from a holder, because TreeKEM needs every commit. Which exit is it? (a) Retention tied to the slowest active member's acknowledged revision. (b) Treat it as admission: a re-Welcome by any admin (S8 (b) or later). (c) A new §2 entry, which needs an ADR amending 0088. Recommended: (b), with (a) as an optimisation. **S5's acceptance is gated on this answer.** Until it is ruled, Consequences keeps the holder-only liveness failure.
- **Q6. Operational values** (recommendations with sizing):
  - Retention: 128 events per group, today's in-memory cap; at 51.5 KB each that is 6.6 MB, under a 16 MiB per-group cap; 256 MiB per node.
  - Requester: 16 outstanding fetches and 3 holders at once, mirroring ADR 0089's requester budgets; one request per (digest, holder) per 30 s.
  - Responder: the existing staging caps (`control_blob.rs:14-20`) and 8 requests per requester per 10 s.
  - Timeouts: 10 s for an inline answer; the existing 115 s for a blob pull.
  - Head probe: every 5 minutes while a group is open.
  - Completion: H1 moves two 51.5 KB events, about four 32 KiB chunks, well inside one 115 s pull.
- **Q7. "S8" in 0088's acceptance order.** S8 (b) (0114) depends on S4, so "S2 and S8" can only mean S8 (a). Confirm that S5 does not wait for 0114.
- **Q8. The subject's certificate on Home gossip.** The gossiped Home `MemberAdded` still carries the joiner's own `certificate_b64`, which receivers require (`named_groups.rs:11249-11255`). Removing it means receivers apply a digest-only add pending a fetch, which is a new acceptance rule, and old receivers would reject such adds. Does S2 or S5 own that change, under D38?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
