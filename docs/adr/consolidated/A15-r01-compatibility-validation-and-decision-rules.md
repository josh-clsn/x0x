# A15 Compatibility Validation and Decision Rules

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Agreed by David on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These are the agreed review drafts. Formal replacement acceptance remains pending.
Use the [index and transition rules](README.md) to interpret their status.

x0x will have no more than 15 current ADR slots. The new set must preserve important decisions and evidence while making the current architecture easier to read.

## Context

There are 100 numbered ADRs in the reviewed snapshot. Many mix decisions with implementation plans, detailed protocols and review history.

Current CI protects accepted ADR text and associated frozen evidence. Code, tests and open PRs refer to those records. A file move alone would not create a safe replacement.

## Decision

Use stable current IDs [A01](A01-r01-purpose-and-product-limits.md)–A15. Archived records and previous accepted revisions do not count towards the limit.

Each current slot has a clear subject. A change to that subject uses a proposed new revision, such as [A07](A07-r01-messages-receipts-history-and-retry.md) revision 2. David accepts the replacement. The earlier accepted revision remains unchanged in the archive.

A current-version index selects one accepted revision per active slot. Proposed revisions remain visibly Proposed. An agent cannot accept them or create A16.

Target 500–1,000 words per ADR. Review records above 1,500 words. Keep the key guarantees, alternatives and consequences in the decision record.

Supporting specifications contain wire layouts, complete state machines, schemas and test detail. They may evolve only within the accepted guarantees. A material authority or compatibility change requires a new accepted revision.

## Language

Use approximately 80% ASD-STE100 style in ADRs, other documentation, and communication with David. Use short sentences, common words, clear actions and consistent terms. Keep necessary technical terms. This is a writing target, not a claim of formal compliance. Follow the [documentation style guide](../../documentation-style.md).

## Archive transfer

Draft the new set beside the old set. For each old record and important clause, record one disposition: retained, changed by a later accepted decision, retired, or unresolved.

A Proposed old design remains unresolved until it is explicitly accepted. A summary must not turn it into an accepted or shipped feature.

Retain exact old accepted text and frozen evidence. Preserve old paths during the initial transition. Update code and documentation references through a complete mapping.

Existing team work keeps its original acceptance gates until the replacement decisions take effect. Do not combine the archive move with a protocol change.

Update governance CI before changing the governed layout. The new checks must preserve the old protections, not disable them.

## Compatibility

Version persisted and wire formats. Refuse malformed or unsupported data with a clear result. Do not silently replace unreadable authority state with an empty permissive state.

Gate incompatible behavior on verified capability evidence. Unknown capability is not proof of support.

Document upgrade and downgrade limits. Test state produced by a real supported older release. Preserve retained data when a downgrade cannot read it.

Release builds must use the tested dependency graph and lockfile. A source-level test result does not establish that a different published binary passed.

## Validation

Each architectural guarantee has an owning test or evidence path. Important tests exercise the real dispatch and failure boundaries, including meaningful negative controls.

Keep test traffic isolated from production. Tests that can join the real network must use the approved isolated Linux environment.

Separate design acceptance, code merge, CI results, publication and deployed service evidence. None is a substitute for the others.

## Consequences

Readers get a small stable set of decisions. Detailed specifications and historical records remain available. The transfer needs careful review before the new set can replace the rules used by current teams.

## Alternatives

Deleting the old records would remove rationale and make existing references difficult to interpret.

Keeping the old set as the only guide preserves history but retains the reading burden.

Compressing all detail into 15 large records would change the file count without simplifying the architecture. We reject that approach.

## Acceptance

Verify all 100 record mappings and complete the clause-level transfer. Check archived hashes, frozen evidence, links, revision chains and the 15-slot limit.

Publish one short current capability guide. Update the repository instructions and documentation mirror when the migration is applied.

## Matters to settle

David agreed the 15-slot direction and asked for this PR on 5 October 2026. Complete the transfer review and acceptance controls before declaring the old set historical rather than governing.

## Existing decision records

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0025 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0025-required-gates-prove-observation-completeness.md) · [ADR 0063 Rejected](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md) · [ADR 0085 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0085-persisted-binary-formats-are-versioned.md) · [ADR 0087 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0087-repository-and-release-governance.md) · [ADR 0093 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0093-capability-advert-registry.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
