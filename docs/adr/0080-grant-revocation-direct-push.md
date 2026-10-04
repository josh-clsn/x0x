# ADR 0080: A Grant Revocation Is Also Pushed as One Signed Record to Capable Recipients; Gossip Remains the Backstop

- **Status:** Proposed
- **Date:** 2026-09-27 (first draft); revised 2026-10-04 under D63
- **Decision owners:** David Irvine (#994 Root decision, 2026-09-27; D23; D63)
- **Author:** OMP (first draft); revised by Claude (Opus)
- **Reviewers:** cross-model review required before acceptance; David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** [ADR 0077](./0077-share-grant-owner-side-redelivery-outbox.md)
  (owner-side revocation ordering). ADR 0077 is not edited. ADR 0070 §2
  (ShareGrant) and ADR 0018 (revocation records) are not changed.
- **Serves:** goal **A** (an owner shares a chosen agent with another
  person, scoped, expiring and revocable) and requirement **R5** (share a
  subset of my agents). Invariants **I7** (revocation reaches every gate
  within a bound) and **I9** (a wire change is gated by a signed capability
  bit). Wave W4, item A4.
- **Related:** #1003 (this work), #994, #1108 (revocation surface gaps),
  #1111 (Critical revocation carriers), #1116 (corrupt store fails open),
  #891; rulings D23, D35 and D28 in the
  [rulings digest](../design/x0x-direction.md), and D63 (2026-10-04: revise
  this ADR); [ADR 0093](./0093-capability-advert-registry.md) (capability
  bits) and its allocation table in the [ADR index](./README.md);
  [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (the
  allocation procedure); ADR 0098 (prov., the revocation surface); ADR 0074
  s3 (live-session teardown); ADR 0072 (scope freeze).

## Context

**What happens today (main).** `DELETE /grants/:id` signs a `ShareGrant`
revocation record with the owner key. ADR 0077 orders it against grant
redelivery. When the call returns, the owner install has made the record
durable, removed the outbox entry, and will start no new send of the grant.

The record then reaches other daemons only by gossip on
`x0x.revocation.v3`. A daemon that holds the grant keeps honouring it
until that gossip arrives. A grant DM that was already on the wire can
also land after the revoke. The window is seconds on a connected mesh. It
has no bound across partitions or for offline daemons.

The v3 carrier has two more limits:
- It is Normal priority, so it is sheddable (#1111).
- It re-publishes the owner's whole v3 set, not the one new record. A v3
  batch may be up to 2 MiB.

**The first draft of this ADR** pushed the whole v3 batch to each
recipient under a new typed-DM prefix, with no capability check. Review
found three faults:
- An old receiver does not ignore an unknown typed prefix. It treats the
  payload as an ordinary DM: it stores it in DM history and passes the raw
  bytes to DM subscribers.
- A whole v3 batch can exceed the DM payload limit of 49,152 bytes.
- "One push" against "three attempts" was ambiguous.

**The rulings.** D23 gives the revocation surface to ADR 0098 (prov., not
yet drafted). ADR 0098 supersedes ADR 0018 and covers: no revocation sweep
before `not_after`, an owner issuer path for Machine revocation, Critical
carriers for the revocation topics, a fail-closed store, one listing, and
a lost-device response. D35 adds a 90-day maximum ShareGrant lifetime with
renewal (ADR 0098). D35 also holds obligation-carrying typed sends to a
peer of unknown capability for up to one advert period after a restart.
D23 says to revise this ADR as a **capability-gated single-record push**,
and to apply both before any `shed_normal` default. D63 orders that
revision.

**A hold applies.** D28 holds ADR 0070 and ADR 0077: no new slices until
their review is recorded. Code under this ADR is a new grant slice.

## Decision Drivers

- Close the window at the daemons that hold the grant. Owner-side
  ordering (ADR 0077) is already sound and stays as written.
- An old receiver must never get the push (I9). A capability bit is the
  only safe test.
- One record per recipient. It must fit one DM with a wide margin.
- One verify path and one ingest path. A pushed record and a gossiped
  record are the same bytes and must have the same effect.
- Stay inside ADR 0098's scope. Do not decide what ADR 0098 decides.
- Goal E: small, bounded bytes per revoke; no new periodic task; no new
  durable state.

## Considered Options

1. **Capability-gated single-record push** (chosen). Push the one new
   record to each recipient whose current verified advert sets a new ADR
   0093 bit. Gossip stays the backstop.
2. **The first draft: an ungated whole-batch push.** Rejected. Old
   receivers leak the bytes into DM history and subscribers. The batch can
   exceed the DM limit. It also re-sends records the recipient does not
   need. It conflicts with D23.
3. **A durable push with an ACK through the owner outbox.** Rejected for
   now. It turns a best-effort accelerator into an obligation with new
   per-recipient durable state. Gossip, the ADR 0098 store rules and
   in-band grant presentation already cover a missed push. Revisit if
   `Outbox<T>` (ADR 0090, prov.) makes the cost small.
4. **Critical carriers only (ADR 0098).** Not enough alone. Priority stops
   shedding, but it does not shorten gossip latency or cross a partition.
   D23 rules for both.
5. **Status quo (gossip only).** Rejected by the #994 Root decision and by
   D23.
6. **Grantee-side poll.** Rejected. It adds a request type and a reply that
   must verify like a carrier. It does not reach the hosts that enforce the
   grant.
7. **Amend ADR 0077.** Rejected. ADR 0077 is Accepted and immutable, and
   delivery and revocation propagation are separate lifecycles.

## Decision

We will push the one signed revocation record of a revoked grant, as a
typed DM, to each recipient of that grant whose current verified capability
advert sets `grant_revocation_push_v1`. The push is best-effort. The
`x0x.revocation.v3` gossip carrier is unchanged and stays the backstop.

### 1. Capability bit

- **Name:** `grant_revocation_push_v1`. **Proposed bit:** 3, the next free
  bit in the canonical allocation table in the ADR index.
- **Meaning:** "Accepts the single-record grant revocation push
  (`x0x-grant-revocation-push-v1\0`) and ingests it through the v3
  revocation path."
- **Allocation:** this ADR reserves bit 3 in the canonical table, as ADR
  0089 did for bit 2. The bit is effective only when this ADR is Accepted.
  No build advertises it before then. If another ADR takes bit 3 first,
  this ADR takes the next free bit. The name and meaning do not change.
- **Advertising:** a receiver advertises the bit only when its typed route
  for the prefix is registered and ready. A pending receiver does not.
- **Gate direction:** the sender needs **positive evidence**. Bits 0 and 1
  hold a send only when a current advert lacks the bit. This bit is
  stricter: the sender pushes only when a current verified advert **has**
  the bit. Unknown, expired and card-only state means "no push". The push
  is optional and an old receiver mishandles it, so a missed push costs
  only latency.

### 2. Wire format

- **Payload:** `x0x-grant-revocation-push-v1\0` followed by
  `bincode(RevocationRecord)`.
- **Exactly one record.** It is not a `Vec`. Its bytes are the same as that
  record's encoding inside the v3 gossip batch.
- **Subject:** `ShareGrant` only, with a finite `grant_expiry`. A record
  for an unknown grant (`grant_expiry = u64::MAX`) is never pushed. It
  travels by gossip only.
- **Size:** at most 8 KiB, prefix included. The record that
  `DELETE /grants/:id` signs is about 5.4 KB: an ML-DSA-65 public key
  (1,952 B), a signature (3,309 B) and about 100 B of fields, with no
  reason text. That is well under the 49,152-byte DM limit.
- **Signer:** the grant owner's user key. That is the record's existing
  signature. Nothing new is signed. The DM envelope is signed by the
  sending agent as for any DM, but it gives no authority.

### 3. Sender

- **Trigger:** `DELETE /grants/:id`, after ADR 0077's durable step
  succeeds (the record and the outbox removal are both durable). If the
  DELETE answers 503, there is no push. The caller's retry pushes. The
  owner never pushes a revocation that a restart could forget.
- **Grant:** only a grant in this install's issued store. Its expiry gives
  the record a finite `grant_expiry`.
- **Recipients:** the grant's delivery recipient set, computed at revoke
  time:
  1. the daemons of the shared agents, other than this one. These hosts
     enforce the grant, so they come first;
  2. the grantee's known agents;
  3. the `deliver_to` agents, if the install recorded them (open
     question 5).

  The push adds no discovery fan-out beyond this set.
- **Gate per recipient** (section 1):
  - A current verified advert has the bit: push.
  - A current verified advert lacks the bit: skip, and count
    `skipped_not_capable`.
  - Capability is unknown (for example after a restart): ask for one
    bounded targeted advert refresh, as ADR 0093 allows. Wait up to one
    advert period (D35; 600 s today) for a current advert. Push if it has
    the bit. Otherwise skip, and count `skipped_unknown_capability`.
- **Send:** an ordinary typed DM. The route is not durable-registered. The
  sender waits for no ACK.
- **One push:** one logical push per recipient per revoke. It is at most 3
  send attempts. The sender retries only when the local send returns an
  error. A send that returns success ends that push, because no ACK
  exists.
- **No new durable state.** Pending pushes live in memory only, at most
  1,024 at a time. A push over that bound is skipped and counted. A
  restart drops pending pushes. Gossip still carries the record.
- **The DELETE response:** the success contract stays ADR 0077's. The
  DELETE does not wait for pushes. It reports `push_recipients`, the
  number of pushes scheduled. Results go to `/diagnostics` counters:
  `pushed`, `send_failed`, `skipped_not_capable`,
  `skipped_unknown_capability` and `skipped_bound`.

### 4. Receiver

The receiver handles the prefix in this order. It stops at the first
failure.

1. **Route.** The typed route owns the prefix. The bytes never reach DM
   history or DM subscribers, on success or failure. The prefix joins the
   production typed-prefix table, so the raw path catches it before the
   inbox starts.
2. **Decode.** At most 8 KiB. Decode exactly one `RevocationRecord` and
   consume every byte. Otherwise drop and count `malformed`.
3. **Subject.** `ShareGrant` with a finite `grant_expiry`. Otherwise drop
   and count `wrong_subject`.
4. **Stale.** If the record is past its GC horizon (`grant_expiry` plus
   the existing slack), drop and count `stale`. The grant can no longer
   be honoured.
5. **Duplicate.** If the set already holds a revocation for the same
   `(owner, grant_id)`, drop and count `duplicate`. No signature verify is
   done.
6. **Rate.** At most 16 pushes per minute from one sending agent, and 256
   per minute in total. Drop the excess and count `rate_limited`.
7. **Verify.** The same authority check as the v3 carrier: the owner's
   ML-DSA-65 signature over the record's canonical bytes, and the issuer
   key must hash to the record's `owner`. On failure, drop and count it
   with the forged-v3 counter. Every verify is counted.
8. **Ingest.** As a one-record batch through the same v3 ingest path,
   under the same owner-trust revocation barrier. Persist through the same
   store writer (section 6). Everything a v3 insert triggers also fires
   for a pushed record. That includes live-session re-evaluation once ADR
   0074 s3 lands.

The receiver does not need to hold the grant. A push can arrive before the
grant DM that it revokes. The receiver stores the revocation, and the
existing revocation check refuses the late grant.

The sending agent's identity gives no authority. It is used only for the
rate limit and the counters. A valid record relayed by anyone has the same
effect, because the record carries its own authority.

### 5. Idempotence, replay and ordering

- **Idempotence.** The key is `(owner, grant_id)`. A second push, the
  gossip copy, or a new record from a retried DELETE is a duplicate. It
  changes nothing and costs no verify.
- **Replay.** A revocation only ever removes access. A replayed valid
  record cannot grant or widen access. It can only re-state a revocation
  the owner signed. Steps 4 to 6 bound the work a replay can cause: a
  stale record is dropped, a duplicate is dropped before verify, and each
  sender is rate-limited. The push needs no nonce and no recipient
  binding. The record is public and is gossiped to everyone anyway.
- **Order on the owner.** Durable record (ADR 0077), then the v3 gossip
  publish (unchanged), then the push. The push never runs before the
  record is durable. Gossip and push do not wait for each other.
- **Order on the receiver.** Either carrier can arrive first. The result
  is the same.
- **Order against the grant DM.** See section 4: a late grant is refused.
- **Order against outbox redelivery.** Ingest takes the same barrier as
  the v3 carrier. No redelivery of the grant starts after either carrier
  ingests.
- **Gossip schedule.** The v3 carrier still re-publishes the whole set on
  change and on its fallback tick. This ADR does not change that.

### 6. The revocation store (#1116)

Today a `revocations-v3.bin` that fails to decode loads as an empty set
(fail-open). The v3 writer then rewrites an undecodable file from memory.
ADR 0098 makes the store fail closed (D23). This ADR does not decide how.
It sets these rules for the push path only:

- A pushed record is written only through the same store writer as a
  gossiped record. There is no separate push store and no separate
  listing. The one listing that ADR 0098 defines shows pushed records too.
- A pushed record is never the write that replaces a store file that
  failed to load. If the v3 store failed to load in this run, the push
  applies the record in memory only and counts `persist_held`.
- If a write fails, the record stays in memory. The daemon fails closed
  for this run, as for gossip, and counts the failure.
- A push carries one record. It never counts as a full re-sync. If ADR
  0098 holds gates until a full re-sync, a pushed record is applied and the
  hold stays.
- The push does not repair #1116. It is sent once, at revoke time. It does
  not restore the older records that a lost store held.

### 7. Alignment with ADR 0098 and D35

- This ADR does not depend on ADR 0098 to be correct, and it decides
  nothing that ADR 0098 decides. The points that touch ADR 0098 are open
  questions 1 to 4.
- **No sweep before `not_after`.** Share-grant revocations are already
  collected only at their grant's GC horizon, not by the 90-day sweep. The
  push uses the same horizon. With D35's 90-day maximum lifetime, every
  pushed record becomes collectable within about 90 days.
- **Critical carriers (#1111).** The push complements Critical carriers.
  It does not replace them. D23 requires both before any `shed_normal`
  default.
- **Machine issuer path and lost device (#1108).** Out of scope. The push
  carries `ShareGrant` records only.
- **One listing.** Pushed records live in the same set, so they appear in
  the same listing.
- **Renewal (D35).** How a renewed grant relates to its revocation is open
  question 2.

### 8. Sequencing

- ADR 0087 rule 8: this is a wire change. The code merges to `main` only
  after this ADR is Accepted.
- D28: the code is a new ADR 0070 and ADR 0077 slice. It waits for their
  hold to lift (open question 7).
- D23: both this push and ADR 0098's Critical carriers land before any
  `shed_normal` default.

## Consequences

### Positive

- At each capable host, the window shrinks from "gossip propagation" to
  "one DM". That includes hosts behind a partition that a direct path still
  reaches.
- Old receivers never see the push. Nothing leaks into DM history or to DM
  subscribers.
- One record per recipient. It fits one DM with a wide margin.
- One verify path, one ingest path and one store. No new durable state.

### Negative / Trade-offs

- One more typed-DM prefix and one more capability bit to carry.
- A host without the bit, or with unknown capability, gets only gossip.
  During a mixed-version period, many hosts may be in that state.
- The owner learns nothing from a successful push, because there is no
  ACK. The DELETE reports what it scheduled, not what arrived.
- Until the `deliver_to` list is recorded, a `deliver_to` daemon that is
  neither a host nor a grantee agent gets only gossip.
- The push does not repair #1116 or #1111. ADR 0098 must still land.

### Neutral / Operational

- ADR 0077's ordering text stays authoritative. This ADR adds propagation
  only.
- `/diagnostics` gains sender counters (section 3) and receiver counters
  (section 4).
- **Efficiency (E-D15).**
  - Audience: the recipients of one grant only.
  - Rate: once per revoke per recipient, plus at most 2 retries on a local
    send error.
  - Bytes: about 5.4 KB of record plus about 4.5 KB of DM envelope (an
    ML-KEM-768 ciphertext, an agent ML-DSA-65 signature and headers), so
    about 10 KB per recipient in one direction, and no ACK bytes. These
    figures are estimates from the key and signature sizes, not
    measurements.
  - Verifies: one per new record at the receiver. A duplicate costs none.
    All are counted.
  - Persistence: O(change), one record merged into the existing file.
  - No new periodic task. The only queue is the bounded in-memory pending
    set.
  - Compatibility carrier: none. The push is never sent to a peer without
    the bit, so no sunset is needed. The cost of the v3 whole-set
    re-publication is out of scope.

## Validation

Tests for the implementing PR. Each one needs a recorded red run.

1. **The push alone revokes.** With gossip disabled, a capable host that
   stored the grant stops honouring it after the push. Red: push disabled.
2. **The push arrives before the grant.** The push lands first. The
   delayed grant DM is refused and not stored.
3. **The gate.**
   - A recipient whose current advert lacks the bit gets no push DM.
   - Unknown capability: one refresh is requested, then the push is
     skipped.
   - A card-only claim does not count.
   - A receiver without the route gets nothing in DM history or
     subscribers.

   Red: gate disabled.
4. **Forged or malformed pushes are refused.** Each case is dropped, counted
   and leaves no state and no DM history: a wrong key, a foreign owner,
   tampered bytes, a non-`ShareGrant` subject, an unknown grant
   (`u64::MAX`), a `Vec` payload, trailing bytes, and an oversize payload.
   Red: verify disabled.
5. **Idempotence and replay.** Same record twice; gossip then push; push
   then gossip; two records from a retried DELETE. Each gives one effect.
   Duplicates leave the verify counter unchanged. A record past its GC
   horizon is dropped.
6. **Order against outbox redelivery.** At another owner install, a pushed
   record and a concurrent redelivery pass go through the same barrier. No
   redelivery starts after the ingest.
7. **The store.**
   - A failed persist keeps the record in memory and counts it.
   - A v3 store that failed to load is not overwritten by a push
     (`persist_held`).
   - Once ADR 0098 lands, a push does not end a re-sync hold.
8. **The owner.** A DELETE that answers 503 sends no push. Its retry does.
9. **Mixed versions** (sealed testnet, the release-gate row style). 0.45
   and pre-bit 0.46 receivers get no push and no DM history entry, and
   gossip still revokes the grant.

**Revisit** when ADR 0098 is drafted, when renewal is designed, or if
`Outbox<T>` makes a durable push cheap.

## Open questions for David

1. **Lost device.** Should ADR 0098's Machine and Agent revocations, the
   lost-device response, reuse this push under their own bit and prefix?
   This ADR covers `ShareGrant` records only.
2. **Renewal (D35).** If a renewal keeps the `grant_id`, the revocation's GC
   horizon must cover the latest renewal. Otherwise a late renewal could be
   honoured after the revocation is collected. If a renewal gets a new
   `grant_id`, a revoke must cover the whole chain, so a push may carry one
   record per live id. ADR 0098 decides, and this ADR follows.
3. **The fail-closed form (#1116).** ADR 0098 chooses between refusing to
   start and a quarantine with a hold until re-sync. This ADR works with
   both. Please confirm that a pushed record may be applied in memory
   during a hold.
4. **Live sessions.** ADR 0074 s3 tears down live sessions within 5 s of
   receipt. Please confirm that the bound counts from receipt over either
   carrier.
5. **`deliver_to`.** Should the issued-grant entry record its `deliver_to`
   list, so the push reaches those daemons? That is a versioned
   share-grant store change (ADR 0085). The recommendation is yes, in the
   implementing slice.
6. **The bit.** Bit 3, with the positive-evidence gate in section 1, and
   the unknown-capability wait of one advert period from D35. Please
   confirm, or set a shorter wait.
7. **The D28 hold.** Does this slice wait for the ADR 0070 and ADR 0077
   review, or is it exempt as part of the D23 revocation work?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
