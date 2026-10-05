#!/usr/bin/env python3
"""W3-H (#1164) determinism gate.

Every W3-H case writes its canonical trace to `<dir>/<case>-<pid>.trace`
(see `Sim::finish`). After a `--stress-count N` run, this script requires,
for every case:

- exactly N traces (`--runs N`);
- every trace byte-identical (one canonical digest);
- the trace recorded `entropy=controlled` (the preload shim was active).

`--require CASE` names cases that must be present. On a mismatch it prints
the first divergent line of the canonical trace. Exit 1 on any failure.
"""
import argparse
import difflib
import hashlib
import sys
from collections import defaultdict
from pathlib import Path


def load(directory):
    cases = defaultdict(list)
    for path in sorted(Path(directory).glob('*.trace')):
        case, _, _pid = path.stem.rpartition('-')
        if case:
            cases[case].append((path.name, path.read_text()))
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--runs', type=int, required=True)
    parser.add_argument('--require', action='append', default=[])
    args = parser.parse_args(argv)
    problems = check(args.directory, args.runs, args.require)
    for problem in problems:
        print(f'W3H-GATE FAIL {problem}', file=sys.stderr)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
