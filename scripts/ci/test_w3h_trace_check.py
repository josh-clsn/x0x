#!/usr/bin/env python3
"""Unit tests for scripts/ci/w3h-trace-check.py (the W3-H determinism gate)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'w3h_trace_check', Path(__file__).with_name('w3h-trace-check.py'))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

TRACE = '# w3h canonical trace v1 seed=0x1\n[marks]\n  @0us case c entropy=controlled\n'


class TraceCheckTest(unittest.TestCase):
    def write(self, directory, name, text):
        Path(directory, name).write_text(text)

    def test_identical_traces_pass(self):
        with tempfile.TemporaryDirectory() as d:
            for pid in range(3):
                self.write(d, f'w3h_case-{pid}.trace', TRACE)
            self.assertEqual(CHECK.check(d, 3, ['w3h_case']), [])

    def test_divergent_trace_fails_with_first_divergence(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE)
            self.write(d, 'w3h_case-2.trace', TRACE.replace('@0us', '@5us'))
            problems = CHECK.check(d, 2, [])
            self.assertEqual(len(problems), 1)
            self.assertIn('first divergence', problems[0])
            self.assertIn('@5us', problems[0])

    def test_wrong_run_count_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE)
            self.assertIn('w3h_case: 1 traces, expected 20', CHECK.check(d, 20, []))

    def test_uncontrolled_entropy_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(d, 'w3h_case-1.trace', TRACE.replace('controlled', 'uncontrolled'))
            self.assertTrue(any('not controlled' in p for p in CHECK.check(d, 1, [])))

    def test_missing_required_case_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(CHECK.check(d, 1, ['w3h_missing']),
                             ['w3h_missing: no trace written'])


if __name__ == '__main__':
    unittest.main()
