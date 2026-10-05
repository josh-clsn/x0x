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

    def test_appendix_is_not_compared(self):
        with tempfile.TemporaryDirectory() as d:
            for pid, stop in enumerate(('@9us', '@12us')):
                self.write(d, f'w3h_case-{pid}.trace',
                           f'{TRACE}{CHECK.APPENDIX}\n  {stop} teardown verified\n')
            self.assertEqual(CHECK.check(d, 2, ['w3h_case']), [])

    def test_divergence_before_the_appendix_still_fails(self):
        with tempfile.TemporaryDirectory() as d:
            tail = f'{CHECK.APPENDIX}\n  @9us teardown verified\n'
            self.write(d, 'w3h_case-1.trace', TRACE + tail)
            self.write(d, 'w3h_case-2.trace', TRACE.replace('@0us', '@5us') + tail)
            problems = CHECK.check(d, 2, [])
            self.assertEqual(len(problems), 1)
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

    def receipt(self, d, pid, verdict, stages=('setup_done', 'evidence', 'request_delivered',
                                               'cause', 'final')):
        import json
        body = {'schema': 'w3h.receipt/1', 'case': 'w3h_red', 'verdict': verdict,
                'stages': [{'stage': stage} for stage in stages]}
        self.write(d, f'w3h_red-{pid}.receipt.json', json.dumps(body))

    def test_expected_red_receipts_pass(self):
        with tempfile.TemporaryDirectory() as d:
            for pid in range(2):
                self.receipt(d, pid, 'RED')
            self.assertEqual(CHECK.check_receipts(d, 2, ['w3h_red=RED']), [])

    def test_infra_receipt_is_not_red(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'RED')
            self.receipt(d, 2, 'INFRA')
            problems = CHECK.check_receipts(d, 2, ['w3h_red=RED'])
            self.assertTrue(any('verdict INFRA' in p for p in problems), problems)

    def test_red_receipt_missing_cause_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.receipt(d, 1, 'RED', stages=('setup_done', 'evidence', 'request_delivered', 'final'))
            problems = CHECK.check_receipts(d, 1, ['w3h_red=RED'])
            self.assertTrue(any("lacks stages ['cause']" in p for p in problems), problems)


if __name__ == '__main__':
    unittest.main()
