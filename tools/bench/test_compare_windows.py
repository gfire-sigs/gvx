import unittest

from compare_windows import owned_process_metrics


class OwnershipTest(unittest.TestCase):
    def test_reused_parent_pid_does_not_attribute_existing_app(self):
        entries = [(10, 1, "runner"), (20, 10, "sentry"), (21, 20, "stub"),
                   (30, 10, "existing_app"), (31, 30, "existing_child")]
        metrics = {pid: {"pid": pid, "created_ticks": created, "private_commit_bytes": 100}
                   for pid, created in ((10, 100), (20, 110), (21, 120), (30, 50), (31, 60))}

        owned, excluded = owned_process_metrics(entries, [10], metrics.__getitem__)

        self.assertEqual({row["pid"] for row in owned}, {10, 20, 21})
        self.assertEqual(sum(row["private_commit_bytes"] for row in owned), 300)
        self.assertEqual(excluded, [])

    def test_inaccessible_child_reports_missing_ownership_evidence(self):
        entries = [(10, 1, "runner"), (20, 10, "child")]
        metrics = {10: {"pid": 10, "created_ticks": 100}, 20: {"pid": 20, "error": 5}}

        owned, excluded = owned_process_metrics(entries, [10], metrics.__getitem__)

        self.assertEqual({row["pid"] for row in owned}, {10})
        self.assertEqual(excluded, [{"pid": 20, "error": 5}])


if __name__ == "__main__":
    unittest.main()
