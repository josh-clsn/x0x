# Transfer map for the 15 ADR set

Source commit: `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. The source set contains 100 numbered ADRs.

Every row has one primary home. Related ADRs can cite other slots.
**All clause reviews remain pending.** A mapping is not formal supersession.

| Source ADR | Status at source | Primary home | Clause review |
|---|---|---|---|
| [ADR 0001: Bootstrap Peers Are Seed Hints Only](../0001-bootstrap-peers-are-seed-hints-only.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0002: Application-Level Keepalive for Direct Connections](../0002-application-level-keepalive-for-direct-connections.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0003: Auto-Connect to Discovered Agents](../0003-auto-connect-to-discovered-agents.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0004: QUIC Stream and Channel Limits for Gossip Workloads](../0004-quic-stream-and-channel-limits.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR-0005: mDNS Local Network Discovery](../0005-mdns-local-network-discovery.md) | Superseded | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0006: No Global DHT Dependency for User and Group Data](../0006-no-global-dht-for-user-and-group-data.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0007: Three-Layer Identity Model](../0007-three-layer-identity-model.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0008: Trust Evaluation System](../0008-trust-evaluation-system.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0009: Receive-Pump Overload Policy](../0009-recv-pump-overload-policy.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0010: GSS Before MLS TreeKEM for v1 Secure Groups](../0010-gss-before-mls-treekem-for-v1-secure-groups.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [0011 — Bootstrap nodes dual-listen on UDP/443; clients dial 443 first and never bind privileged ports](../0011-bootstrap-dual-listen-udp-443.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0012: Real TreeKEM as the Default Secure Group Plane](../0012-treekem-default-secure-groups.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0013: Priority-Aware PubSub Receive-Pump Shedding](../0013-priority-aware-pubsub-shed.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0014: TreeKEM Self-Leave Is a Roster Removal; PCS Comes From an Owner-Driven Rekey](../0014-treekem-self-leave-owner-driven-rekey.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0015: No App-Layer At-Rest Encryption or Secondary Passwords](../0015-no-app-layer-at-rest-encryption.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0016: Role-Based Group Authority — Flat Admin/Member, Retiring `Owner`](../0016-role-based-group-authority-flat-admin.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0017: Position x0x as the agent transport layer (spec + A2A interop + PQC/zero-registry positioning)](../0017-x0x-as-agent-transport-layer.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR-0018 — Key Lifecycle: Expiry, Renewal, and Revocation](../0018-key-lifecycle-expiry-renewal-revocation.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0019: Connect ACL — default-closed connectivity policy](../0019-connect-acl-default-closed.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0020: Tailnet Phase 1 — per-peer byte-streams + local port-forwarding](../0020-tailnet-phase-1-byte-streams-and-forwarding.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0021: DM origin-machine attestation for gossip DMs](../0021-dm-origin-machine-attestation.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0022: Tailnet stream API — per-protocol acceptors, connect-ACL gate, bounded backpressure](../0022-tailnet-stream-api.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0023: Durable Local History Is a Core x0x Capability](../0023-durable-local-history.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0024: GSS Rotation on Admin Remove Is Fail-Closed and Seals Before It Persists](../0024-gss-rotation-on-admin-remove-fail-closed.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0025: Required Gates Must Prove Observation Completeness](../0025-required-gates-prove-observation-completeness.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0026: Managed x0xd Deployment Has Distinct Roots and Closed Resolution](../0026-managed-x0xd-deployment.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0027: Active-Recipient Group-Key Sealing](../0027-active-recipient-group-key-sealing.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0028: Authenticated Causal-Predecessor Delivery](../0028-authenticated-causal-predecessor-delivery.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0029: First-Class Threading on Signed Public Group Messages](../0029-public-message-threading.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0030: DM Protocol v2 — Durable Application ACK, Capability-Gated](../0030-dm-durable-application-ack-v2.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0031: Sole-Member Self-Leave Deletes the Group](../0031-sole-member-self-leave-deletes-group.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0032: The `:443` Bootstrap Listener Runs Its Own Identity](../0032-x0xd-443-own-identity.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0033: The Receive Pump Never Blocks — All Classes Shed or Spill](../0033-recv-pump-never-blocks.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0034: Leaf Gossip Participation Is the Desktop Default; `--relay` Is One Operator Concept](../0034-leaf-participation-default.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0035: Relay Decentralization to SOTA — Earned Promotion, Spread Selection, Bootstrap Demotion](../0035-relay-decentralization.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0036: Owner Singleton and Naming Registry](../0036-owner-singleton-and-naming-registry.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0037: Agent Placement and Key Custody](../0037-agent-placement-and-key-custody.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0038: Home — an Owner-Certified Personal Space](../0038-home-owner-certified-personal-space.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0039: Agent Harness Boundary — ACP-Attached Agents vs API-Key Riders](../0039-agent-harness-boundary.md) | Accepted | [A04](A04-r01-agent-attachment-and-inbound-events.md) | Pending |
| [ADR 0040: Agent-to-Agent Delegation in Spaces](../0040-agent-delegation-in-spaces.md) | Accepted | [A12](A12-r01-agent-teams-delegation-and-task-coordination.md) | Pending |
| [ADR 0041: Cross-Machine State Sync — Tiered, Owner-to-Owner Only](../0041-cross-machine-state-sync-tiers.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0042: Voice Media over Tailnet Streams (`WebRtcV1`)](../0042-voice-media-over-tailnet-streams.md) | Accepted | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0043: Agent Key-Move Protocol — Machine KEM Enrollment, Commit-then-Activate Moves, Binding Revocation](../0043-agent-key-move-protocol.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0044: The Daemon Exposes a Loopback REST + WebSocket + SSE Control Plane](../0044-daemon-local-rest-ws-sse-control-plane.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0045: Decentralized Self-Update with Signed Manifests and Transactional Restart](../0045-decentralized-self-update.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0046: Exec Runs Only Exact-Argv Allowlisted Commands, Fail-Closed, Audited](../0046-exec-service-fail-closed-acl.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0047: The KV Store Is CRDT-Backed with Delta Gossip and a Context-Gated `Encrypted` Policy](../0047-crdt-kv-store-delta-gossip.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0048: Task Lists Coordinate via Per-Entity CRDTs with Signed Provenance](../0048-crdt-task-list-coordination.md) | Accepted | [A12](A12-r01-agent-teams-delegation-and-task-coordination.md) | Pending |
| [ADR 0049: Presence Runs on Signed Beacons over a Global Topic with FOAF Candidate Scoring](../0049-presence-foaf-discovery.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0050: Direct Messages Ride a KEM-Sealed, Signed, Replay-Protected Gossip Base](../0050-dm-over-gossip-base-transport.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0051: Peer Relay (X0X-0070) Is a Default-Off, One-Hop DM Fallback](../0051-application-level-peer-relay.md) | Proposed | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0052: The GUI Is a Compile-Time-Embedded HTML Asset Served by the Daemon](../0052-embedded-gui-in-daemon-binary.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0053: An API-Unserved Watchdog on a Dedicated Thread Aborts a Wedged Daemon](../0053-api-unserved-watchdog.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0054: External Agent Signing Uses a Canonical Domain-Separated Context, Never Raw Payloads](../0054-external-agent-signing-dst.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0055: File Transfer Is a DM-Chunked, SHA-256-Verified Protocol with a 1 GiB Cap](../0055-dm-file-transfer-protocol.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0056: Voice Link Transport and Signaling (Historical Record; Media Ratified by ADR-0042)](../0056-voice-link-transport-and-signaling.md) | Superseded | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0057: Local Apps Reach the Daemon via REST/WS with Filesystem Discovery; `serve()` Is the Embedded Form](../0057-embedded-serve-library-local-apps.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0058: The Constitution Is Embedded Compile-Time in Every Binary](../0058-compile-time-embedded-constitution.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0059: Invite Authentication and Seating Provenance](../0059-invite-authentication-and-seating-provenance.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0060: The Owner's Home Is Elected, Not Per-Install](../0060-one-home-per-owner.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0061: Self-Update Must Resolve Restart Ownership Before Replacing Binaries](../0061-supervised-upgrade-restart-ownership.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0062: Recover Ordinary Home Persistence as One Durable Pair](../0062-home-persistence-pair-recovery.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0063: Signed KV legacy gossip compatibility adoption boundary](../0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md) | Rejected | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0064: Owner-Anchored Fork Authority for Invite-Derived Seatings](../0064-owner-anchored-fork-authority.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0065: Duplicate Homes Are Inventoried, Not Retired](../0065-duplicate-home-inventory-retirement-deferred.md) | Superseded | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0066: Ordinary-Group Fork Anchors and Data-Plane Quarantine Coverage](../0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0067: The Lifecycle Epoch Token Is Derived Marker Identity, Not a Generation Counter](../0067-lifecycle-epoch-token-is-derived-marker-identity.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0068: Fork Quarantine Pins History Retention and Buffers Inbound Task Deltas](../0068-quarantine-pinned-history-retention-and-buffered-task-deltas.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0069: Home Auto-Provisioning Waits for Owner Sync](../0069-home-wait-for-sync-before-auto-provisioning.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0070: Owner Trust and Share Grants](../0070-owner-trust-and-share-grants.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0071: Relay Backbone — What Relays Today and What Is Deferred](../0071-relay-backbone-shipped-truth-and-deferred-work.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0072: Scope Freeze — Deferred and Legacy-Maintenance Mechanisms (2026-09-25)](../0072-scope-freeze-deferred-and-legacy-maintenance.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0073: Audio and Video Calling Ship Together via the Daemon-Side Browser Gateway](../0073-audio-and-video-calling.md) | Accepted | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0074: Tailnet Phase 2 — Names, Persistent Forwards, SOCKS5 and Open-Stream Revocation](../0074-tailnet-phase-2-names-persistent-forwards-socks5.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0075: Collaborative Notes Use a yrs Text CRDT in the Group Store; Agent Scratchpads Are a Rider-Reachable Group Store](../0075-collaborative-notes-and-agent-scratchpads.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0077: Share-Grant Redelivery Is an Owner-Side Durable Outbox; Grantee Fetch Deferred](../0077-share-grant-owner-side-redelivery-outbox.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0079: Grant-Carried Owner and Machine Names as ADR-0074 §1 Name Defaults](../0079-grant-carried-owner-and-machine-names.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0080: A Grant Revocation Is Also Pushed as One Signed Record to Capable Recipients; Gossip Remains the Backstop](../0080-grant-revocation-direct-push.md) | Proposed | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0081: Notes Use the loro Text CRDT (Supersedes the ADR-0075 CRDT Choice)](../0081-notes-use-loro-crdt.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0082: Note Records Are Accepted Under the Roster Epoch They Were Written At](../0082-notes-epoch-bound-writer-rule.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0083: Agents Show Their Owner a GUI View, Locally or on the Owner's Active Machine](../0083-agent-initiated-gui-show.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0084: Admit Owner Sync from Enrolled Machines on Verified Enrollment Alone](../0084-enrolled-owner-sync-admission.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0085: Persisted Binary Formats Are Versioned, Read Every Released Layout, and Fail Closed on Downgrade](../0085-persisted-binary-formats-are-versioned.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0086: Gossip Send Targets Are Bounded by Transport Connectivity](../0086-gossip-send-targets-bounded-by-transport-connectivity.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0087: Repository and Release Governance: Protected Main, Admin-Only Release Tags, a Reviewed Release Environment, and ADRs Before Code](../0087-repository-and-release-governance.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0088: Group Liveness Contract (I8)](../0088-group-liveness-contract.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0089: Relationship-Peer Evidence Survives Restart (Evidence Rule, Slice 1)](../0089-relationship-peer-evidence-survives-restart.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0093: Capability Advertisement Registry](../0093-capability-advert-registry.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0094: M2 safe apply with launcher-owned rollback](../0094-m2-safe-apply.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0095: Scope — x0x Is Glue Between People, Their Machines and Their Agents](../0095-scope-x0x-is-glue.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0096: R12 — x0x Is Maintained by Its Own Agents](../0096-r12-x0x-is-maintained-by-its-own-agents.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0106: Join Results Carry the Intervening Membership Events](../0106-join-result-carries-intervening-membership-events.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0107: Stuck Join Re-arm and Current-Roster Serving Guard (0088 S8 (a))](../0107-stuck-join-rearm-and-serving-guard.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)](../0108-home-scoped-owner-certificate.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)](../0109-ownerless-attestation-self-recovery.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0110: Revocation Eviction, Designated First](../0110-revocation-eviction-designated-first.md) | Proposed | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)](../0111-evidence-size-k-and-fetch-by-hash.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0112: Any-Admin Invite Redemption (0088 S6)](../0112-any-admin-invite-redemption.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)](../0113-home-is-an-explicit-owner-group-adopted-in-place.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows](../0114-authority-re-welcome.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |

## Required transfer evidence

For each important clause, record the source section, destination section,
disposition, reason, human decision where needed, and owning test or evidence.
Preserve frozen grounding files with their accepted records. Recheck the map
against main before activation; source records can change while teams work.

An old Proposed, Rejected or Superseded record does not become Accepted
because this map links to it. Read the existing status overlay as well.
