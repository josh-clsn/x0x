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
  - Allocates [ADR 0093](./0093-capability-advert-registry.md) registry bit 2, following 0093's allocation procedure.
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
  - a fleet restart at N = 1000 is O(N) per node (see Costs).

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

### 3. How evidence is used

**On load (startup, in the background, never blocking the API):**
1. Re-verify every record.
2. Drop any record that fails verification, is revoked, has an expired certificate, or no longer has a relationship.
3. Seed `AuthenticatedMachineBindings` from the valid records.

After this:
- The existing `raw_delivery_verified` (`src/lib.rs:3962`) marks a raw frame from (A, M) `verified`. This covers #1088 and #1089.
- The existing registry-backed grant check (rule 2) and owner trust find the binding.

**Certificates.** `evaluate_grant_access` rule 4 and owner trust read the certificate from the evidence store when the discovery cache has none.

**Send side (#1091).** `send_direct` resolves A's KEM key in this order:
1. the capability store;
2. **the evidence advert**;
3. the contact card.

The strict durable-ACK path may use the evidence advert, because it is agent-signed and machine-bound. It still refuses the unauthenticated contact card, as today. The dial address comes from the evidence announcement when the discovery cache has none.

**The discovery cache is not seeded.** Presence and "online" views stay based on fresh announcements.

**Capability bits (ADR 0093 freshness is unchanged).** A persisted advert's registry bits are treated as **unknown**, not as current support or missing support, until a fresh advert arrives. Per 0093, unknown sends as before. Holding typed sends during a post-restart grace window is D35, not this slice.

### 4. Freshness, staleness and revocation

- **Monotonic.** A record is replaced only by valid evidence whose announcement `announced_at` and advert `created_at` are both newer. An older replay can never roll a binding back. This matches `AuthenticatedMachineBindingCache::record`.
- **Maximum age.** A record whose newest timestamp is older than **30 days** is not used for `verified` or for sealing. A fresh exchange or pull must refresh it first. The limit is configurable as `[evidence] max_age_days`, with a minimum of 1.
- **Revocation.** Checked on load, on every ADR-0018 revocation insert, and at the point of use. A record is removed when:
  - its agent, machine or (agent, machine) binding is revoked;
  - its certificate user is revoked;
  - its certificate expires;
  - its enrollment is gone, which includes an unenroll (#1055).
- **Relationship ends.** When a member is removed, a grant expires or is revoked, or a device is unenrolled:
  - the record is removed within one sweep (60 s);
  - it stops being used immediately at the point of use.
- **Machine moves (known residual).** If A moved to a new machine while this node was down, the old record keeps verifying frames from A's *previous* machine until newer evidence arrives. Frames from the new machine stay unverified, which fails closed.
  - That previous machine held A's key under the same owner.
  - A hostile previous machine is handled by the ADR-0043 retired-binding revocation, which removes the record.

### 5. Wire: the on-connect exchange and the pull lookup (`EvidenceV1`)

**A new ADR-0022 stream protocol, `EvidenceV1 = 0x06`.** There is no new gossip topic and no broadcast.

- **Admission.**
  - Admitted from any **transport-authenticated** machine, including one with no known agent. That is the restart case, which today's gate denies with `deny_not_verified`.
  - The content is self-authenticating, so admission grants no trust. It only lets bytes arrive, under the bounds in §6.
  - Nothing received is persisted unless it is valid (§1) **and** names a relationship peer (§2). Evidence for strangers only refreshes the in-memory TTL caches.
- **Hello (on connect).** When a connection to machine M comes up, and M either hosts a relationship peer or is an enrolled machine, each side sends one `Hello` in each direction:
  - It carries the sender's **own** current `announcement` and `advert` bytes, plus its certificate digest. The certificate itself is sent only if the peer's `Hello` did not already name that digest.
  - The receiver accepts a `Hello` only if its (A, M) names **the transport-authenticated M**. A peer can present evidence only about itself.
- **Pull (on demand).**
  - Used when a send, a raw frame or a grant check needs agent X and holds no valid record.
  - The node sends `Lookup { agent_id: X }` to at most **3** connected machines that share a relationship context with X: the same group, the same owner, or the grant counterparty.
  - The reply is `Found { announcement, advert, certificate? }` for X, or `NotFound`. It is served only from the responder's own identity or its valid evidence store.
  - The requester re-verifies everything (§1), so a lying responder can only withhold evidence or serve older evidence, which monotonicity then ignores.
- **Framing.** A 1-byte message type, then a length-prefixed bincode body.
  - The evidence parts are carried as their existing signed wire bytes, verbatim. There is no re-encoding, so no new signature scheme.
  - Each message is at most **32 KiB**.
- **Capability bit.** ADR 0093 registry **bit 2, `peer_evidence_v1`**: "accepts `EvidenceV1` streams".
  - A sender with a current verified advert lacking the bit skips the stream.
  - With unknown advert state, which is the restart case, it tries once per connection. A reset (see §7) marks the connection "no evidence" until it drops.

### 6. Bounds (goal E)

**Costs.** One ML-DSA-65 verify is taken as ≤ 1.5 ms. That is the conservative saturated-VPS figure from #656; it is much less on idle hosts.

| Item | Cost |
|---|---|
| Record on disk | about 23 KB. The store is capped at **512 records (about 12 MB)**, evicting in the order group-member, then grant-party, then enrolled-device, oldest first. |
| Load at startup | 4 verifies per record (announcement, advert base, advert trailer, certificate). R = 50 takes about 0.3 s of CPU; the 512 cap takes ≤ 3 s. It runs in the background. |
| `Hello` | about 23 KB each way (about 16 KB when the certificate digest is known) and ≤ 4 verifies at the receiver. **At most one per connection establishment** per machine; reconnect flaps are limited to one `Hello` per machine per 60 s. |
| `Lookup` | ≤ 23 KB reply and ≤ 4 verifies. The requester makes at most 1 lookup per target per 30 s, to ≤ 3 responders. A responder answers ≤ 8 lookups/s per connection and ≤ 32 lookups/s in total, and excess is refused. |
| Stream admission | a global cap of **32 evidence verifies/s** per node. Excess `Hello`/`Lookup` bodies are dropped unverified; they are retried on the next connection or the next pull. |

**Per-node cost when the whole fleet restarts,** with C = connections per node (typically 8, capped by `max_connections`) and R = relationship peers:

| Fleet size | This ADR (per node) | #1092 re-announce (per node) |
|---|---|---|
| N = 100 | ≤ min(C, R) Hellos: typical 8 × 23 KB = **184 KB**, **32 verifies** (worst case C = 64: 1.5 MB, 256 verifies) | N announcements received: 100 × 7.4 KB = **740 KB**, ≥ **100 verifies** |
| N = 1000 | **unchanged**: 184 KB, 32 verifies (worst case 1.5 MB, 256 verifies) | 1000 × 7.4 KB = **7.4 MB**, ≥ **1000 verifies (≥ 1.5 s CPU)** per re-announce round |

The exchange is O(C), independent of N. The re-announce is O(N) on a global topic.

### 7. Mixed versions

- **v0.45 and earlier map the unknown protocol byte `0x06` to `None` and reset the stream.** That costs one round trip per connection, with no effect on state.
- **The 0.46 side still uses its persisted evidence.** The evidence it holds for a 0.45 peer came from that peer's own gossip announcement and advert, which 0.45 publishes.
- **Row 4b** (a restarted rc sender to a 0.45 receiver within 5 min) is covered by persisted evidence alone.
- **The #1092 reconnect re-announce** is retired once `EvidenceV1` ships:
  - A 0.45 peer that restarts still learns about us from our regular 600 s heartbeat. That is its existing behaviour.
  - The typed `RecipientUndiscovered` error from #1092 stays.

### 8. Storage format (ADR 0085)

**File layout.**
- **Path:** `<data_dir>/peer-evidence.bin`.
- **Layout:** `X0PEV1\0\0` (8 bytes), then bincode `EvidenceFileV1 { records: Vec<EvidenceRecordV1> }`, with the fields of §1.
- **Positional encoding:** any change to the shape needs a new magic and a frozen v1 decoder, per ADR 0085 rules 1 and 2. Bodies must be consumed exactly.

**Reading and writing.**
- **Unreadable file:** an unknown magic or a failed decode starts the node **without** evidence. The file is left untouched and a WARN is logged; it is never deleted.
- **Writes:** atomic (temp file, fsync, rename), debounced to at most one per 10 s.

**Downgrade.** v0.45 never reads this file, so a downgrade ignores it and a re-upgrade reuses it.

**Fixture.** A fixture file generated by the released encoder is added when the format ships (ADR 0085 rule 6).

### 9. Security argument: #898 and #1070 still hold

1. **Nothing becomes `verified` without authenticated evidence naming this transport-authenticated machine.**
   - The store admits only mutual signed evidence (§1).
   - The raw path still compares the claimed (A, M) against it.
   - A frame from (A, M′) with a record for (A, M) stays `verified = false` and never rebinds. This is the #898 rule.
2. **Disk tamper cannot forge anything.**
   - Every record is re-verified on load.
   - The worst tamper can do is delete or roll back records, which only makes the node colder. Monotonicity stops a rolled-back file from overriding newer in-memory evidence.
3. **A replay of genuine old evidence** is ignored while newer evidence is held. It is bounded by the 30-day maximum age and removed by revocation.
4. **A peer cannot inject bindings for others through `Hello`.** Pull answers are verified end to end and cannot be forged.
5. **Revocation and expiry apply** on load, on insert and at the point of use (§4). A revoked sender is dropped exactly as today (`peer_revoked` follows `verified`).
6. **The #1070 gates are unchanged.** They now receive `verified = true` for relationship peers after a restart, which is what #1070 intended.
7. **Strangers gain nothing.** They are never persisted, and their evidence only refreshes the existing TTL caches (E-D10).
8. **No secrets at rest are added.** The file holds only public keys, signatures and certificates, so ADR 0015 is unchanged.

## Consequences

### Positive

- **Immediate recovery after a restart.** DM, Welcome push and fetch, file offers, grants and owner sync to known peers work straight away, with no 600 s wait. #1088, #1091 and the grant-after-restart gap close by construction, not by patching one path at a time.
- **ADR 0084 becomes a special case.** The on-connect `Hello` gives the enrolled machine's agent directly.
- **Efficiency.** Point-to-point, O(C) recovery replaces O(N) global re-announces (goal E).

### Negative / Trade-offs

- **New surfaces.** A new stream protocol, a new persisted file (≤ about 12 MB) and a new ADR 0093 bit.
- **Machine-move residual.** A peer that moved machines while this node was down can still be verified on its old machine until fresh evidence arrives (§4).
- **Background verify cost at startup:** ≤ 3 s of CPU at the record cap.
- **A persisted advert's capability bits are unknown after restart.** Mixed-version typed sends right after a restart behave as before (D35 is separate).
- **The relationship set is only as fresh as local state.** A member added elsewhere is a stranger until this node applies that roster change.

### Neutral / Operational

- **Diagnostics counters:** `evidence_loaded`, `evidence_rejected_on_load{reason}`, `evidence_hello_sent/received`, `evidence_lookup_sent/served/refused`, `evidence_bytes_{in,out}` and `evidence_verifies`. They feed the goal-E budgets.
- **ADR 0021's stateless attestation is kept unchanged.** This store is an addition for the raw lane and the send side, which attestation does not cover.

## Validation

**Unit tests (inert):**
- **Round-trip and format:**
  - the format round-trips;
  - a v1 fixture from the released encoder loads;
  - an unknown magic starts cold, with the file untouched;
  - trailing bytes are rejected.
- **Tamper and rejection:**
  - tampering with any signature, id or key is rejected on load;
  - a mismatched (A, M) pair is rejected;
  - an older record never replaces a newer one;
  - a record past the maximum age is not used.
- **Revocation on load:**
  - a revoked agent, machine or binding is dropped;
  - a revoked certificate user is dropped;
  - an expired certificate is dropped;
  - an unenrolled device is dropped.
- **Relationship changes:** removing a member, revoking or expiring a grant, or unenrolling a device evicts the record, and use stops immediately.
- **Cap and E-D10:** the cap evicts in the stated order, and evidence about a stranger is never persisted.
- **Raw path:**
  - an empty discovery cache plus an evidence record for (A, M) gives a raw frame from (A, M) `verified = true`;
  - a frame from (A, M′) stays unverified (#898);
  - a revoked A is dropped.
- **`EvidenceV1`:**
  - a `Hello` naming a machine other than the transport machine is refused;
  - a `Lookup` reply is verified and never trusted on its own;
  - the rate caps and the 32 KiB limit hold;
  - a reset from an old peer marks the connection and is not retried.

**Integration (CI, isolated), red on origin/main and green on the fix:**
- **Welcome:** restart B cold, and warm A pushes a Welcome. The seat must leave `pending_authority_commit` within **5 s**.
- **DM:** restart B cold, and **B sends first** to A. The DM must succeed within **10 s**.
- **Grant:** restart the host of a granted agent. The grantee's first request must be admitted within **10 s**.
- **Owner sync:** restart an owner device cold. The owner-sync session must complete within one pass (≤ 60 s), with no gossip announcement needed.

**D30 release-gate row, restart-cold** (a CI test plus a testnet row):
- Restart a node with cold caches.
- Within the bounds above, run each of these:
  - a DM both ways;
  - a TreeKEM join with Welcome;
  - a file offer;
  - owner sync.
- **Row 4b:** a restarted rc sender reaches a **0.45** receiver within 5 min. Persisted evidence alone should do it in about 10 s.

**Cost check:**
- Record the fleet-restart bytes and verifies per node on the testnet against §6.
- **E-D17:** delivered must equal published for every flow in the gate row.

**Review triggers:**
- any change to the record contents, the relationship set, the 30-day maximum age, the caps, or `EvidenceV1` admission;
- any proposal to persist strangers or to seed the discovery cache from the store.

## Notes for AI-assisted work

- **Persist signed source bytes, never derived fields,** and re-verify them on load.
- **Never mark `verified` from a record naming a different machine** than the transport-authenticated one.
- **A `Hello` carries only the sender's own evidence.** Only a `Lookup` reply may carry a third party's, and the requester re-verifies it.
- **Do not seed the discovery cache or capability bits from the store.**
- **Do not persist strangers.**
- **Must not be marked Accepted without David's review.** This ADR is Proposed.
