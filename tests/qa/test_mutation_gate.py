"""Mutation gate: every in-repo defect we inject must be killed.

This test is intentionally opt-in via ``QA_MUTATION=1`` because it copies the
package and spawns subprocesses for each mutant (a few seconds).
"""

from __future__ import annotations

import os
import unittest

import mutation


@unittest.skipUnless(os.environ.get("QA_MUTATION") == "1", "set QA_MUTATION=1")
class TestMutationGate(unittest.TestCase):
    def test_all_mutants_are_killed(self):
        outcomes = [mutation.evaluate(m) for m in mutation.MUTATIONS]
        survivors = [o.mutation.name for o in outcomes if not o.killed]
        self.assertEqual(survivors, [])


if __name__ == "__main__":
    unittest.main()
