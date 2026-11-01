# T-leaf-caps-consume-only: a leaf consumes the caps topics but does not forward them

- **Status:** Proposed (fork tail, leaf-quiet lane, caps part).
- **Date:** 2026-10-25
- **Base:** `survivor-rekey` at `c71d222e`; saorsa-gossip-pubsub `0.5.87`
- **Upstream:** x0x#504 (Leaf egress tracker), E-D6 step 2 "S3: consume-only Leaves"; risk x0x#1455
- **Drop at:** when upstream ships S1 (unicast caps) or S3 (consume-only Leaves), whichever lands first. Consume theirs and delete this arm. Nothing is on the wire, so no migration is needed.

## Context

Every daemon subscribes to the four mesh-wide DM-capability topics (`x0x/caps/v1`, `x0x/caps/v1/request/targeted-v2`, `x0x/caps/v1/response/targeted-v2`, `x0x/caps/v2/digest`). `leaf_mode` trims other whole-network topics but never touched these. A subscribed topic is forwarded under C3, so a leaf re-published every other node's adverts, requests and responses to its eager peers and announced them by IHAVE to the rest.

On a one-claude agent (`leaf_mode = true`) over 22.4 h, that was 11.6 GB uploaded, all of it epidemic forwarding. About 9.8 GB was caps, about 4.35 GB of that IHAVE. The forward demand also kept the Leaf egress limiter saturated and cost about half a core.

The leaf cannot simply stop subscribing. Caps is the only way a strict (`require_durable_app_ack`) sender learns a contact's or stranger's signed KEM key and machine binding: a card is never enough for a strict send, and ADR 0089 evidence covers relationship peers only. Noetic's planned direct-first mode sends to contacts, so that row must keep working.

**Upstream.** x0x#504 is open. Its 2026-09-30 plan orders the work S1 (unicast caps) first, then S3 (consume-only Leaves) "only once Full-node relay capacity is budgeted", then S4 (enforced `shed_normal`), scheduled for W4 (Q1-Q2 2027). Neither S1 nor S3 exists upstream. x0x#1455 is the matching risk: a leaf's eager frame landing on a non-forwarding bystander pushes about 45% of durable sends onto the 250 ms bus fallback.

**Why now, before S1.** The cost is real today and falls on our users' uplinks and batteries. Our leaves are a tiny share of the mesh, so the Full nodes and bootstraps carry the tree and S3's capacity precondition is not strained by them. The change is one verdict arm on a validator x0x already owns, uses an sg verdict that already exists, and is wire-invisible.

## Decision

- **Key.** `[gossip] caps_consume_only = <bool>`, optional. Unset follows the daemon's `leaf_mode`, so every metered leaf (Noetic desktop, Android embed, noetic-agent) gets it with no template change. An explicit `true` or `false` overrides; `false` is the A/B and escape hatch. A value that is not a boolean reads as unset, and the loader warns about it (`ConfigFindings::ignored_values`); this leniency is for this key only. A Full node never goes consume-only: the daemon resolves an explicit `true` there to off and logs a warning. Resolved once at startup (`GossipConfig::apply_caps_consume_only`, called from `daemon_gossip_config` in `server/mod.rs`), the same way `skips_legacy_dm_bus` is.
- **Scope.** The four caps topics only, named once in `dm_capability::CAPS_TOPIC_NAMES`. The advert service destructures that array to subscribe, inbound attribution classes it as `caps`, and the verdict reads it, so the three cannot drift. Identity announce, revocation and the DM inbox topics are unchanged.
- **Mechanism.** `RelayFanout::verdict` returns sg `ValidationAction::DeliverOnly` for a consume-only topic, after the base (storm-control) validators and before C2/C3. The message is delivered to local subscribers and never eager-forwarded or IHAVE-announced. A base `Drop` still wins. `PubSubManager::configure_egress` installs the set only on a Leaf with an explicit `Some(true)`.
- **Unchanged.** Subscriptions, own publishes (local origin skips validators, and #774 gives a leaf a Full eager peer), answering targeted requests, the advert cadence and every wire format.
- **Counter.** `GET /diagnostics/gossip` `relay_fanout` gains `consume_only` (bool), `consume_only_msgs` and `consume_only_msgs_by_topic` (per caps topic name). They count x0x's own DeliverOnly verdicts, so storm control's are not mixed in.

## Consequences

- A consume-only leaf uploads only its own caps. Inbound is unchanged, because full peers still feed it every caps message; only S1 removes that.
- **Anti-entropy residual.** DeliverOnly messages stay cached and serveable, so the 30 s digest exchange can still serve one. It is small and shows in `pubsub_stages.outbound_by_kind.anti_entropy`. Removing it needs a "deliver, never serve" sg verdict.
- **A chain made only of consume-only leaves does not carry caps.** A - B - C with no Full node: B delivers A's caps and forwards nothing, so C hears them only if the anti-entropy exchange repairs it. Production leaves dial Full bootstraps, so the path between two leaves runs through a Full node, which forwards as before.
- **#1455 class.** Other nodes that hold a leaf in their caps eager set now see their frame stop there, repaired by their IHAVE or anti-entropy. A strict refresh has a 3 s window, so a chain made only of consume-only leaves can miss it. Full nodes carry the tree; watch #1455.
- **Fork tail.** One verdict arm, one config key, one diagnostics block. It is offered on #504 with before and after numbers.

## Tests

- `relay_fanout`: `consume_only_caps_topics_are_deliver_only_and_counted`, `consume_only_never_widens_a_base_drop`, `empty_consume_only_set_changes_nothing`.
- `gossip::config`: `caps_consume_only_unset_follows_leaf_mode_and_explicit_overrides`, `caps_consume_only_is_off_with_a_warning_on_a_full_node`, `caps_consume_only_mistyped_value_reads_as_unset`.
- `server`: `caps_consume_only_resolves_from_leaf_mode_and_participation`, `a_misspelt_caps_key_is_reported_and_falls_back_to_leaf_mode`, `a_mistyped_caps_value_warns_and_falls_back_to_leaf_mode`.
- `gossip::pubsub`, line topology publisher → leaf → third peer on the test recorder: `caps_consume_only_leaf_delivers_caps_locally_and_forwards_nothing`, `caps_consume_only_overrides_both_ways_and_full_forwards_as_before`, `caps_consume_only_leaves_non_caps_topics_unchanged`, `caps_consume_only_leaf_still_publishes_its_own_caps`.
- `gossip::pubsub`, hermetic three-node meshes: `caps_converge_leaf_to_leaf_through_a_full_node` (consume-only leaf A to Full F to consume-only leaf B: B receives every message on all four topics, F forwards, B counts each under the verdict) and `caps_do_not_cross_a_chain_of_consume_only_leaves` (A - B - C, all consume-only, anti-entropy cut: C receives none).
- `caps_consume_only_tests::strict_dm_goes_out_on_a_capability_learned_by_a_consume_only_leaf`: two real Agents, both consume-only leaves; the sender learns the recipient's durable capability only through a DeliverOnly verdict, and a strict DM is durably acknowledged and delivered.

## Field acceptance

An A/B on the one-claude agent, 1 h per leg, `caps_consume_only = false` then the default. Expected with consume-only: upload and `participation.epidemic_forward_bytes` down at least 80%, caps eager and IHAVE rows at own-origin only, `egress_budget.leaf_egress.queue_overflow` about 0, CPU under 5% of a core, and `relay_fanout.consume_only_msgs` growing at about the caps inbound rate.

The A/B must also read `pubsub_stages.outbound_by_kind.anti_entropy` on both legs. That is the residual this change leaves: cached caps ids still go out in the 30 s digests, and cached messages are still served to a digest sender that lacks them. The review estimates the digests at about 64 KB per hot topic per 30 s at worst (sg's cache is 60 s and 2048 entries at most), about 170 MB/day, against about 10 GB/day before. Nobody has measured it yet.
