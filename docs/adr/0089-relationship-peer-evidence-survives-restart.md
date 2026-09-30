# ADR 0089: Relationship-Peer Evidence Survives Restart (Evidence Rule, Slice 1)

- **Status:** Proposed
- **Date:** 2026-09-30
- **Decision owners:** David Irvine (decision; charter D29), Claude x0x-32 (drafting)
- **Reviewers:** Codex or OMP (cross-model review); David Irvine (acceptance, required before any code merges)
- **Supersedes:** none. It replaces the #1092 reconnect re-announce stopgap (D31) once implemented.
- **Superseded by:** none
- **Amends:** [ADR 0021](./0021-dm-origin-machine-attestation.md) (Accepted, not edited):
  - It rejected option 2, "a persistent binding cache", because it "adds disk state to a security boundary".
  - This ADR adopts a persistent binding store **for relationship peers only**, as an *addition* to stateless origin attestation, which stays as it is.
  - ADR 0021's rule that origin authentication "MUST work with zero prior discovery-cache state" still holds.
- **Also:**
  - Allocates [ADR 0093](./0093-capability-advert-registry.md) registry bit 2 through 0093's allocation procedure (a README registry note plus the code constant; 0093 itself is not edited).
  - The persisted file follows [ADR 0085](./0085-persisted-binary-formats-are-versioned.md).
- **Vision requirement and goals:**
  - **R3** (all my machines connected);
  - **R5 / R6** (sharing and collaboration survive a restart);
  - goals **F** (it works) and **E** (measured efficiency).
- **Related:** #1040, #1088, #1089, #1091, #1092, #843, #891, #1055, #1064; charter D29, D30, D31, D33–D35, E-D10; `.planning/design-health-check-2026-09-30.md` §2 R1; `omp-reports/testnet-runs/g46r2/finding3-mechanism.md`; `omp-reports/1088-root-review.md`; `omp-reports/1091-root-review.md`.
- **Scope note:** this is slice 1 of the W3 evidence rule (D17). `Authority::decide`, persisted consent and certificate-in-band admission come later, as a separate ADR that extends this one.

## Context

A restarted daemon forgets everything it knew about the peers it works with. Each piece of that knowledge lives only in memory:

| State | Where (origin/main) | Lifetime |
|---|---|---|
| agent → machine binding (authenticated) | `AuthenticatedMachineBindings`, `src/dm_inbox.rs:145`, 65,536-entry LRU | process only |
| discovery entry (addresses, agent key, `AgentCertificate`) | discovery cache, `src/lib.rs:2040` | 900 s TTL, process only |
| recipient ML-KEM key for DM sealing | `CapabilityStore`, `src/dm_capability.rs:295` (`DmCapabilities.kem_public_key`) | 900 s TTL, process only |
| verified identity announcement | re-broadcast every 600 s on `x0x.identity.announce.v2` | next heartbeat |

Nothing rebuilds them after a restart:
- `announce-blob-cache.bin` persists certificates only, keyed by digest, with no machine and no KEM key.
- `contacts.json` holds unauthenticated machine records.

The only recovery clock is the peer's next 600 s announcement. Each security tightening, while correct on its own, has turned that gap into an outage:

- **#1088 / #1089, receive side.**
  - The raw 0x10 lane marks a frame `verified` only from the discovery cache or the binding registry.
  - #1070 gates Welcome, files, join-result and control-blob on `verified`. The #898 rule says raw claims verify only against recorded evidence.
  - A restarted joiner therefore drops the owner's TreeKEM Welcome, and the seat stalls about 9 min (g46r2, mechanism A).
- **#1091, send side.** A restarted node cannot seal a DM to a peer it already knew: `AgentNotFound` becomes "recipient key material unavailable". The Welcome fetch fails the same way (g46r2, mechanism B).
- **#1040, owner sync.** A restarted device denied its own enrolled machine. ADR 0084 patched this path alone.
- **Grants.** `evaluate_grant_access` (`src/share_grant.rs:~785`) needs the in-memory binding plus a cached certificate, so a grant is inert after a restart.
- **#1092, the stopgap (D31).** It re-broadcasts the node's own announcement on reconnect, which puts point-to-point recovery on a global bus:
  - every re-announce costs every node about 7.4 KB and at least one ML-DSA verify;
  - a fleet restart at N = 1000 is O(N) per node (see §10).

The design health check (R1) judges this a design flaw, not a set of bugs. The node needs durable, self-verifying evidence about the peers it has a relationship with, and a cheap point-to-point way to refresh it.

## Decision Drivers

- **F:** after a restart, DM, TreeKEM Welcome, file offers, grants and owner sync to known peers work immediately, not after 600 s.
- **Keep #898 and #1070:** a raw sender claim is `verified` only on authenticated evidence naming this transport-authenticated machine. No relaxation.
- **E / E-D10:**
  - no global broadcast for point-to-point recovery;
  - bounded bytes, verifies and disk;
  - strangers stay TTL-only.
- **Self-verifying state:** anything persisted is re-verified on load, so a tampered file cannot forge evidence (ADR 0015 posture: no secrets at rest are added).
- **Versioned storage (ADR 0085) and mixed-version safety (ADR 0093).**

## Considered Options

1. **Keep the #1092 reconnect re-announce as the fix.**
   - It is O(N) per node on a global topic.
   - It recovers only when the reconnecting peer is subscribed.
   - Grants and the Welcome fetch still wait for it.
2. **Persist the derived caches (bindings, discovery entries, adverts) as plain records.**
   - Cheap, but the store becomes an unauthenticated security input: disk tamper forges bindings.
   - Rejected for the reason ADR 0021 gave.
3. **Persist signed source evidence for relationship peers, re-verify it on load, and refresh it point-to-point on connect and on demand** (chosen).
4. **Persist evidence for every peer ever seen.**
   - Unbounded disk.
   - Violates E-D10, which keeps strangers TTL-only.

## Decision

### 1. What is persisted: mutual, self-verifying evidence

For each **relationship peer** agent A on machine M, the node keeps one `EvidenceRecord`:

| Part | Bytes | Proves |
|---|---|---|
| `announcement` | the V3 identity announcement wire bytes (`IdentityAnnouncementV3`, `src/announce_v3.rs:97`, about 7.4 KB) | **machine-signed**: M claims to host A. Also carries A's and M's public keys and addresses. |
| `advert` | the DM capability advert wire bytes, with its optional `X0CR` registry trailer (`CapabilityAdvert`, `src/dm_capability.rs:111`, about 8 KB) | **agent-signed** over `agent_id ‖ machine_id ‖ created_at`: A claims to be on M. Carries A's DM **ML-KEM key**. |
| `certificate` (optional) | `AgentCertificate` bytes (about 7.2 KB) | the owner's certificate for A, needed for owner trust and `Grantee::User` matching |
| `relation` | `u8` flags: enrolled-device, grant-party, group-member | why the record is kept |
| `stored_at_ms` | `u64` | local bookkeeping only; never trusted as evidence |

A record is **valid** only when all of these hold:
- both signatures verify;
- the ids are hash-consistent with the embedded public keys;
- the announcement and the advert name the same (A, M);
- the certificate, if present, verifies, binds A and is unexpired.

This is the same mutual evidence that the registry accepts today:
- an agent-signed claim naming the machine;
- plus the machine's own signature, or its live transport authentication.

It must never be derived state.

### 2. Who is a relationship peer

The set is computed from state that already persists, and is re-evaluated on each change and at least every 60 s:

- **Enrolled devices:** the agents on machines in `sync/devices.json` with a current, owner-signed, unrevoked enrollment (ADR 0041, ADR 0084).
- **Grant parties:**
  - the grantees in `share-grants.bin` (an agent, or the agents whose certificate names a granted user);
  - the owner agent of every grant this node holds.
- **Group members:** the active `members_v2` agent ids of every non-withdrawn named group this node is an active member of.

Everything else stays TTL-only, in memory (E-D10). Trusted contacts are not included in this slice.

### 3. Freshness: acceptance is strict, use is bounded (r2, Codex P1-1)

Each signed component is judged **on its own**. The pair is never judged by its newest timestamp.

| Rule | Limit |
|---|---|
| **Future skew** (every component, always) | `announced_at` and advert `created_at` are each ≤ now + 5 min. |
| **Ingest freshness** (evidence arriving from the network: gossip, `Hello` or `Lookup`) | Each component must be at most **30 min** old (2 × the advert TTL of 900 s). An older component is rejected, so a stale agent advert cannot be paired with a fresh machine announcement. |
| **Use limit** (a stored record after a restart) | Each component must be at most **30 days** old (`[evidence] max_age_days`, minimum 1). Past that, the record is treated as absent and needs a fresh `Hello` or `Lookup`. |
| **Watermark** (persisted, per agent) | The highest advert `created_at` ever accepted for agent A, and the machine it named. A record for A is accepted, or used, only if its advert `created_at` ≥ A's watermark. A newer advert naming M_new permanently disqualifies older adverts naming M_old. |

**Watermark storage.**
- Watermarks are kept in the same file.
- They outlive evicted records, with a separate cap of 4096 agents × about 80 B.
- They are never lowered.

**What this bounds.**
- A former machine M_old that kept its machine key can present A's old advert only while that advert is at most 30 min old, and only to a node that has never accepted a newer advert for A.
- That is the same exposure as today's in-memory 900 s capability TTL.
- After that, the ADR-0043 retired-binding revocation still removes it.

**The rollback claim is corrected.**
- Replacing `peer-evidence.bin` with an older genuine copy **does** roll back the watermark and can restore an old binding.
- That needs write access to the data directory, which already allows replacing the node's own keys (the ADR 0015 posture). It is out of scope, not "only colder".
- Tampering *without* genuine old signed bytes still cannot forge anything.

### 4. How evidence is used: at the point of use, never copied (r2, Codex P1-2, P2-3)

The store is **consulted**, never used to seed another cache. There is one call:

`peer_evidence.usable(agent, machine, now) -> Option<EvidenceView>`

It returns a view only if the record exists and all of these hold, re-evaluated on **every call**:
- the record verified at load or ingest;
- it names exactly (agent, machine);
- every component is within the use limit;
- the advert is at or above the watermark;
- the certificate, if present, is unexpired **now**;
- agent A is still in `relationship_set()` **now**;
- none of the agent, machine, (agent, machine) binding or certificate user is revoked **now**.

Removing a record, or any of these conditions failing, removes its authority **immediately**. No other cache holds a derived copy.

**Consumers, each falling back to the store only when its current source has nothing:**

| Consumer | Today's source (origin/main) | Evidence fallback |
|---|---|---|
| Raw delivery `verified` (#1088/#1089) | discovery cache or `AuthenticatedMachineBindings` (`raw_delivery_verified`, `src/lib.rs:3962`) | `usable(A, M)` is `Some`, with cert expiry taken from the view |
| Raw durable-ACK sender key (P2-3) | discovery `agent_public_key` (`src/lib.rs:13740-13761`) | the agent key from the view's announcement |
| Send-side KEM key (#1091) | `capability_store`, then the contact card | order becomes capability store, then **view advert**, then contact card. The strict durable-ACK path accepts the view, never the card. |
| Dial address | discovery | the view's announcement addresses |
| Grant rule 2 binding / rule 4 certificate | registry / discovery certificate | `usable(A, M)` / the view's certificate |
| Owner trust certificate | discovery certificate | the view's certificate |

`AuthenticatedMachineBindings` keeps being filled **only from live evidence**, as today. The store never writes to it. **The discovery cache and ADR-0093 bits are not seeded.** A stored advert's registry bits are treated as unknown.

### 5. What recovers, and what does not (r2, Codex P2-4)

**Guaranteed within the §10 bounds after a restart:** a relationship peer with a **usable stored record**.

**Not guaranteed, with the defined path for each:**

| Case | Path |
|---|---|
| **No file** (first 0.46 start, or an unreadable file) | Cold. On connect, a `Hello` arrives from any peer that sends one (§6). Otherwise `Lookup`, then gossip. |
| **Record past the use limit, evicted, or below the watermark** | Treated as absent: `Lookup` to eligible peers, then gossip. |
| **Contact-only peer** (not a relationship) | Excluded in this slice (E-D10): gossip only, as today. See Open Questions. |
| **Moved peer with no eligible connected intermediary** | Its record names the old machine and verifies nothing new. Recovery waits for its `Hello` when it connects, or for gossip. |
| **Traffic before the background load finishes** | See below. |

**Traffic before the background load finishes.**
- Raw frames and sends that would consult the store wait on a **load barrier**. The wait is bounded: at most 5 s, and at most 64 frames or 1 MiB queued.
- When the barrier releases, they are evaluated normally. On a timeout they are evaluated as if no record existed, which fails closed exactly as today.
- Sends return the retryable `RecipientUndiscovered` (from #1092) instead of a terminal error.

### 6. Wire: `EvidenceV1` (r2, Codex P2-5)

**Protocol.** A new ADR-0022 stream protocol, `EvidenceV1 = 0x06`.
- It is admitted from any **transport-authenticated** machine, even with no known agent.
- It goes only to the evidence acceptor, never the default channel. This is the same narrow pattern as ADR 0084.

**Framing.**
- A 1-byte type, then a length-prefixed bincode body.
- Signed parts are carried verbatim.
- A message is at most 32 KiB, and a stream carries exactly one request and one reply.

**Hello (on connect).** Each side sends its **own** current announcement and advert, plus its certificate digest. The certificate itself follows only if the peer lacks it.
- **Sent** when the connected machine is enrolled, or hosts an agent with a usable stored record or a live relationship.
- **Accepted** only if (A, M) names the transport-authenticated machine and every component passes §3 ingest freshness. Then the evidence is stored if A is a relationship peer. Otherwise it only refreshes the in-memory TTL caches.

**Lookup (pull).** `Lookup { agent_id: X }` is answered with `Found { announcement, advert, certificate? }` or `NotFound`.

**Responder authorization.** The responder serves a request only if all of these hold, and otherwise answers `NotFound` without signalling why:
- the requesting transport machine hosts an agent R that is itself one of the responder's relationship peers, with a usable record or live evidence;
- R and X share a relationship context at the responder: the same group roster, the same owner (both enrolled to the responder's owner), or one is the grant counterparty of the other;
- the reply is built only from the responder's own identity or a usable stored record, never from TTL caches of strangers.

**Responder budgets.**
- Per requesting machine: ≤ 2 open `EvidenceV1` streams, ≤ 1 `Lookup` per 2 s and ≤ **64 KiB/s** of replies.
- Globally: ≤ **256 KiB/s** of replies and ≤ 32 evidence verifies/s, including verifies of `Hello`s received.
- Every stream has a **5 s deadline** covering the first byte to the end of the body. Incomplete or slow streams are reset, and the reset counts against the budget.
- Anything over budget gets `NotFound` or a reset. It is never queued.

**Requester budgets.**
- ≤ 1 `Lookup` per target per 30 s, to ≤ 3 responders.
- ≤ 16 outstanding `Lookup`s in total.
- Replies are re-verified in full (§1, §3) and are never trusted on their own.

**Capability bit.** This ADR allocates ADR 0093 bit 2, **`peer_evidence_v1`**, meaning "accepts `EvidenceV1`".
- A current verified advert lacking the bit means the `Hello` is skipped.
- Unknown state means one try per connection. A reset marks the connection "no evidence" until it drops.
- The allocation is recorded in the ADR 0093 registry through its procedure: a registry note in `docs/adr/README.md` and the code constant. ADR 0093 itself is Accepted and is not edited.

### 7. Mixed versions

- **v0.45 maps the unknown byte `0x06` to `None` and resets the stream** (`src/streams.rs:464-471` on main). The 0.45 behaviour must be proven by a test against the **released v0.45.0 binary** (Validation): the reset, then ordinary DM traffic on the same connection.
- **The 0.46 side uses stored evidence for 0.45 peers,** because 0.45 publishes the announcement and advert pair, and stores it only if the peer is a relationship peer.
- **Row 4b** (a restarted rc sender to a 0.45 receiver within 5 min) is covered by stored evidence. It fails over to gossip when no record exists.
- **The #1092 reconnect re-announce** is retired once `EvidenceV1` ships. `RecipientUndiscovered` stays.

### 8. Storage (r2, Codex P2-7)

**File layout.**
- **Path:** `<data_dir>/peer-evidence.bin`, magic `X0PEV1\0\0`, then bincode `EvidenceFileV1 { records, watermarks }`.
- **Rules:** ADR 0085 rules 1, 2 and 6, with exact consumption.

**Record limits (enforced at ingest, not estimates).**
- announcement ≤ 8 KiB, advert ≤ 12 KiB, certificate ≤ 10 KiB, so a record is ≤ **30 KiB**;
- ≤ **512 records** (store hard cap ≤ 15 MiB) and ≤ **4096 watermarks** (about 330 KiB);
- eviction order: group-member, then grant-party, then enrolled-device, least recently used first.

**An unreadable file is never replaced.**
- On an unknown magic or a failed decode, the store runs **memory-only for the lifetime of the process**. It never writes to or renames over that path.
- A WARN names the file.
- Recovery is manual: move the file aside.
- A test proves the file is byte-identical after the process has received fresh evidence.

**Write coalescing.**
- The file is rewritten only on a **material change**: a record or watermark is added or removed, a binding changes machine, the certificate changes, or a record's stored components are more than 7 days older than live evidence (so they stay inside the use limit).
- A routine re-announcement with a newer timestamp and the same content is **not** material.
- At most one write per 60 s, and only if dirty. A dirty store is also flushed on clean shutdown.
- **Worst case:** 1440 writes/day × 15 MiB = 21 GiB/day, reached only if a material change arrives every minute. Expected: a few writes per day. `evidence_writes` and `evidence_bytes_written` are counters, and the goal-E budget for them is set by E0 measurement.

**Downgrade.** v0.45 never reads the file. A re-upgrade reuses it, and a test covers the round trip.

### 9. Security argument: #898 and #1070 still hold

1. **Nothing becomes `verified` without evidence naming this transport-authenticated machine.**
   - It must be mutual signed evidence, individually fresh at ingest (§3), and currently usable (§4).
   - A frame from (A, M′) with a record for (A, M) stays unverified and never rebinds.
2. **Replay.**
   - A stale advert cannot be paired with a fresh announcement, because ingest freshness is per component.
   - A superseded binding cannot come back while the watermark holds.
   - The residual is the same as today's 900 s capability TTL, plus a local-disk rollback, which is out of scope under ADR 0015.
3. **Lifetime enforcement is at the point of use.** Revocation, certificate expiry, the age limit and relationship removal take effect on the next call, because the store's authority is never copied (§4).
4. **`Hello` carries only the sender's own evidence.** `Lookup` replies are fully re-verified.
5. **Amplification is bounded by the responder** (§6), not by requester goodwill.
6. **The #1070 gates are unchanged.** They now receive `verified = true` for usable relationship peers after a restart.
7. **Strangers are never stored and never served** (E-D10).
8. **Nothing secret is at rest:** only public keys, signatures and certificates (ADR 0015).

### 10. Costs: measured, estimated and enforced (r2, Codex P2-6)

**Verify cost is an assumption to be measured.** `t_v` = one ML-DSA-65 verify.
- 1.5 ms is the saturated-VPS figure from #656 and is used here as a pessimistic **assumption**, not a bound.
- S1 must benchmark `t_v` on the fleet's VPS class and on a Mac, and update this table.

| Item | Enforced ceiling | Typical estimate |
|---|---|---|
| Startup load (R records, 4 verifies each) | R ≤ 512, so 2048 verifies (about 3 s at 1.5 ms, in the background) | R ≈ 50: 200 verifies |
| `Hello` in and out, per connection establishment | 1 per machine per 60 s; ≤ 32 KiB each way | about 16–23 KiB each way; 4 verifies inbound |
| `Lookup` served | 64 KiB/s per requester; 256 KiB/s total | rare: only on a cache miss |
| `Lookup` sent | 16 outstanding; 1 per target per 30 s × 3 responders | rare |
| Evidence verifies (all inbound) | 32/s | — |
| Disk | ≤ 15 MiB; ≤ 1 write per 60 s | a few writes per day |

**Fleet restart, per node, full duplex,** with C = connections (typical 8, capped by `max_connections`) and R = relationship records:

| | This ADR | #1092 re-announce |
|---|---|---|
| **N = 100** | load: 4R verifies (R = 50: 200). Hellos: 2 × min(C, R) × about 23 KiB, which is about **368 KiB** at C = 8, plus 4 × min(C, R) verifies inbound = **32**. Worst case at C = 64: about 2.9 MiB, 256 verifies. Lookups: ≤ 256 KiB/s served. | receive about 100 × 7.4 KB = **740 KB** and ≥ 100 verifies, per re-announce round |
| **N = 1000** | **the same as N = 100.** The load, Hello and Lookup terms depend on R and C, not N. | about **7.4 MB** and ≥ **1000 verifies** per round |

The exchange terms are O(C), and the load term is O(R). Neither grows with N.

## Open Questions for David

1. **Contacts.** Should trusted contacts (not group, grant or enrollment peers) be relationship peers?
   - Excluded here, per E-D10.
   - Including them widens recovery for 1:1 DMs, and grows the store and the `Lookup` authorization surface.
2. **Pre-identity admission.** `EvidenceV1` is admitted from any transport-authenticated machine.
   - The alternative is to admit only enrolled machines and machines named by a stored record. That is tighter, but a moved peer or a new group member then can't send a `Hello` until gossip.
   - The bounds in §6 are what make open admission safe. Keep it open?
3. **Ingest freshness window of 30 min.** A shorter window narrows the replay exposure in §3, but rejects evidence from peers whose adverts are late (clock skew, or advert publish delays after their own restart). 30 min matches today's TTL exposure.

## Consequences

### Positive

- **Relationship peers with a usable record recover after a restart.** DM, Welcome push and fetch, file offers, grants, owner sync and the raw durable-ACK receipt all work without waiting 600 s.
- **The #1088/#1091 and grant-after-restart gaps close by construction,** and lifetime checks sit at one point of use.
- **Recovery is point-to-point.** It is O(C) plus O(R) per node, not O(N) global re-announces (goal E).

### Negative / Trade-offs

- **New surfaces:** a new stream protocol with pre-identity admission (bounded, §6), a new persisted file (≤ 15 MiB), a load barrier (≤ 5 s) and a new ADR 0093 bit.
- **Not every case recovers immediately.** No file, an expired or evicted record, contact-only peers and moved peers without an intermediary are not guaranteed (§5).
- **Replay residual:** at most 30 min of ingest freshness, plus local-disk rollback (§3).
- **Stored capability bits stay unknown after a restart** (D35 is separate).

### Neutral / Operational

- **Diagnostics counters:** `evidence_{loaded,rejected_on_load{reason},usable_hits,usable_misses{reason}}`, `evidence_hello_{sent,received,refused}`, `evidence_lookup_{sent,served,refused,unauthorized}`, `evidence_bytes_{in,out,written}`, `evidence_verifies`, `evidence_writes` and `evidence_load_barrier_waits`.
- **ADR 0021's stateless attestation is unchanged.**

## Validation

**Unit tests (inert):**
- **Format:**
  - a round-trip;
  - a fixture from the released encoder;
  - an unknown magic leaves the store memory-only, and the file stays **byte-identical after fresh evidence arrives**;
  - trailing bytes are rejected;
  - the per-component byte limits hold;
  - the 512-record and 4096-watermark caps hold.
- **Freshness (§3):**
  - a stale advert plus a fresh announcement is rejected at ingest;
  - a future-skewed component is rejected;
  - a record past the use limit is unusable;
  - a record below the watermark is rejected, including across a restart;
  - the watermark survives record eviction.
- **Point of use (§4), each tested *after* load:**
  - revoking the agent, machine, binding or certificate user makes `usable()` return `None` on the next call;
  - so do certificate expiry at the next call, and removing the relationship (member removed, grant expired or revoked, device unenrolled);
  - the store never writes to `AuthenticatedMachineBindings`.
- **Raw path and ACK:**
  - with an empty discovery cache plus a usable record, a frame from (A, M) is verified;
  - (A, M′) is not;
  - a revoked A is dropped;
  - the raw durable ACK verifies against the record's agent key.
- **`EvidenceV1`:**
  - a `Hello` naming another machine is refused;
  - a stale component in a `Hello` is refused;
  - an **unauthorized `Lookup` gets `NotFound`**;
  - a hostile requester is held to 64 KiB/s, 2 open streams and 1 lookup per 2 s;
  - slow and incomplete streams are reset at 5 s;
  - reconnect churn is held to 1 `Hello` per 60 s;
  - the global verify cap holds;
  - an old-peer reset is marked once.
- **Load barrier:**
  - a raw frame and a send arriving during load are held, then evaluated;
  - a timeout fails closed;
  - the send returns `RecipientUndiscovered`.

**Integration (CI, isolated), red on origin/main and green on the fix:**
- **Welcome:** restart B cold with a usable record; warm A pushes a Welcome; the seat leaves `pending_authority_commit` within 5 s.
- **DM:** restart B cold; **B sends first**; the DM and its **durable receipt** complete within 10 s.
- **Grant:** restart the grant host; the first request is admitted within 10 s.
- **Owner sync:** restart an owner device cold; owner sync completes within one pass (≤ 60 s) with no gossip announcement.
- **No file:** the first start after upgrade recovers through `Hello` or `Lookup`; this is a timed measurement, not a pass/fail bound.
- **Expired record:** an expired or evicted record recovers through `Lookup`.
- **Contact-only peer:** it waits for gossip (a pinned current limitation).
- **Traffic during load:** sends and frames arriving during load are held by the barrier, then complete.

**D30 release-gate row, restart-cold (CI test plus a testnet row):**
- Restart a node cold. Within the bounds above, run a DM both ways, a TreeKEM join with Welcome, a file offer and owner sync.
- **Row 4b:** a restarted rc sender reaches a 0.45 receiver within 5 min.
- **0.45 interop:** use the **released v0.45.0 binary** (the CI release artifact) in the isolated harness. Confirm the `EvidenceV1` reset, then ordinary DM traffic on the same connection, and that the 0.46 side marks the connection and doesn't retry.
- **Cost:** record the fleet-restart bytes, verifies and writes per node against §10. E-D17 requires delivered == published for every gate-row flow.

**Review triggers:**
- any change to the freshness limits, the watermark, `usable()` conditions, the relationship set, the caps, the budgets or `EvidenceV1` admission;
- any proposal to persist strangers, or to seed another cache from the store.

## Notes for AI-assisted work

- **Persist the verified signed wire bytes** (never re-serialized structs), and re-verify them on load.
- **The store is consulted at the point of use and is never copied into other caches.**
- **Freshness is per component.** Ingest (30 min) and use (30 days) are separate limits.
- **Never mark `verified` from a record naming a different machine.**
- **A `Hello` carries only the sender's own evidence.** A `Lookup` reply is re-verified and served only to authorized requesters.
- **Never overwrite an unreadable evidence file.**
- **Must not be marked Accepted without David's review.**
