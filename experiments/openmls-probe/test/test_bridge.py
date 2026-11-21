"""Run with python -m unittest discover -s test -p 'test_*.py'."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("max1m_openmls_probe", Path(__file__).resolve().parents[1] / "probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class BridgeTest(unittest.TestCase):
    def test_synthetic_self_test_through_subprocess(self):
        report = probe.run_probe()
        self.assertTrue(report["two_member_exchange"])
        self.assertTrue(report["replay_rejected"])
        self.assertTrue(report["third_member_commit_rejected"])
        self.assertTrue(report["original_rejected_after_tamper"])
        self.assertFalse(report["remove_exposed"])
        self.assertFalse(report["group_persistence_exposed"])
        self.assertFalse(report["usable_for_production"])


if __name__ == "__main__":
    unittest.main()
