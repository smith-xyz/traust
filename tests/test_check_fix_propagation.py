"""Tests for the cross_repo validator rule in validate_report.py; the propagation check itself
runs on traust-core (tests/test_impact_doors.py)."""

import unittest

from traust_engine.reporting.validate import ValidationResult, cross_validate_verification


class TestCrossRepoValidatorRule(unittest.TestCase):
    def _report(self, verdict, propagation, fix_repo="https://github.com/o/lib"):
        return {
            "verified_findings": [
                {
                    "original_id": "X-1",
                    "verdict": verdict,
                    "cross_repo": {"fix_repo": fix_repo, "propagation": propagation},
                }
            ],
            "regressions": [],
            "commit_timeline": [],
            "summary": {},
            "metadata": {"repository": "https://github.com/o/app"},
        }

    def test_pending_resolved_rejected(self):
        r = ValidationResult(file_path="t.json")
        cross_validate_verification(self._report("resolved", "pending"), r)
        self.assertTrue(any("pending" in e for e in r.errors))

    def test_pending_partial_ok(self):
        r = ValidationResult(file_path="t.json")
        cross_validate_verification(self._report("partially_resolved", "pending"), r)
        self.assertFalse(any("pending" in e for e in r.errors))

    def test_same_repo_cross_block_rejected(self):
        r = ValidationResult(file_path="t.json")
        rep = self._report("resolved", "consumed", fix_repo="https://github.com/o/app")
        cross_validate_verification(rep, r)
        self.assertTrue(any("DIFFERENT repo" in e for e in r.errors))


if __name__ == "__main__":
    unittest.main()
