#!/usr/bin/env python3
"""W3-H (#1164) determinism gate.

Every W3-H case writes its canonical trace to `<dir>/<case>-<pid>.trace`
(see `Sim::finish`). After a `--stress-count N` run, this script requires,
for every case:

- exactly N traces (`--runs N`);
- every digested trace byte-identical (one canonical digest);
- the trace recorded `entropy=controlled` (the preload shim was active).

A trace file is the digested canonical trace (everything up to the
`teardown begins` mark), then an `APPENDIX` line and the teardown events.
Only the digested part is compared; a teardown error fails the test itself.

`--require CASE` names cases that must be present. On a mismatch it prints
the first divergent line of the canonical trace.

`--expect CASE=VERDICT` (RED, GREEN or INFRA) checks the red-baseline
receipts (`<case>-<pid>.receipt.json`, schema `w3h.receipt/1`): exactly
`--runs` receipts, every one with that verdict. A RED receipt must carry
every stage (setup_done, evidence, request_delivered, cause, final). Exit 1
on any failure.
"""
import json
import argparse
import difflib
import hashlib
import sys
from collections import defaultdict
from pathlib import Path

# Must match `TRACE_APPENDIX` in src/server/w3h/mod.rs.
APPENDIX = '# --- appendix: teardown (not digested) ---'


def digested(text):
    """The part of a trace file the gate compares (before the appendix)."""
    head, marker, _appendix = text.partition(f'\n{APPENDIX}\n')
    return f'{head}\n' if marker else text


def load(directory):
    cases = defaultdict(list)
    for path in sorted(Path(directory).glob('*.trace')):
        case, _, _pid = path.stem.rpartition('-')
        if case:
            cases[case].append((path.name, digested(path.read_text())))
    return cases


def first_divergence(left, right):
    """The first removed and added lines of the diff, e.g. `- a | + b`."""
    removed = added = None
    for line in difflib.unified_diff(left.splitlines(), right.splitlines(),
                                     lineterm='', n=0):
        if line.startswith(('---', '+++')):
            continue
        if line.startswith('-') and removed is None:
            removed = line
        elif line.startswith('+') and added is None:
            added = line
        if removed is not None and added is not None:
            break
    if removed is None and added is None:
        return '(traces differ only in trailing whitespace)'
    return ' | '.join(part for part in (removed, added) if part is not None)


def check(directory, runs, required):
    problems = []
    cases = load(directory)
    for case in required:
        if case not in cases:
            problems.append(f'{case}: no trace written')
    for case, traces in sorted(cases.items()):
        digests = {hashlib.blake2b(text.encode()).hexdigest() for _, text in traces}
        if len(traces) != runs:
            problems.append(f'{case}: {len(traces)} traces, expected {runs}')
        if any('entropy=controlled' not in text for _, text in traces):
            problems.append(f'{case}: entropy was not controlled (shim missing)')
        if len(digests) != 1:
            base_name, base = traces[0]
            for name, text in traces[1:]:
                if text != base:
                    problems.append(
                        f'{case}: {len(digests)} distinct traces; first divergence '
                        f'{base_name} vs {name}: {first_divergence(base, text)}')
                    break
        else:
            print(f'{case}: {len(traces)} identical traces')
    return problems


RED_STAGES = ('setup_done', 'evidence', 'request_delivered', 'cause', 'final')


def check_receipts(directory, runs, expectations):
    problems = []
    receipts = defaultdict(list)
    for path in sorted(Path(directory).glob('*.receipt.json')):
        case, _, _pid = path.name[:-len('.receipt.json')].rpartition('-')
        try:
            receipts[case].append(json.loads(path.read_text()))
        except json.JSONDecodeError as error:
            problems.append(f'{path.name}: unreadable receipt ({error})')
    for expectation in expectations:
        case, _, verdict = expectation.partition('=')
        found = receipts.get(case, [])
        if len(found) != runs:
            problems.append(f'{case}: {len(found)} receipts, expected {runs}')
        for receipt in found:
            if receipt.get('schema') != 'w3h.receipt/1':
                problems.append(f'{case}: unknown receipt schema {receipt.get("schema")!r}')
                break
            if receipt.get('verdict') != verdict:
                problems.append(f'{case}: verdict {receipt.get("verdict")}, expected {verdict}')
                break
            stages = {stage.get('stage') for stage in receipt.get('stages', [])}
            if verdict == 'RED' and not set(RED_STAGES) <= stages:
                problems.append(f'{case}: RED receipt lacks stages {sorted(set(RED_STAGES) - stages)}')
                break
        else:
            if found and len(found) == runs:
                print(f'{case}: {len(found)} receipts, all {verdict}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--runs', type=int, required=True)
    parser.add_argument('--require', action='append', default=[])
    parser.add_argument('--expect', action='append', default=[],
                        help='CASE=RED|GREEN|INFRA, checked against receipts')
    args = parser.parse_args(argv)
    problems = check(args.directory, args.runs, args.require)
    problems += check_receipts(args.directory, args.runs, args.expect)
    for problem in problems:
        print(f'W3H-GATE FAIL {problem}', file=sys.stderr)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
