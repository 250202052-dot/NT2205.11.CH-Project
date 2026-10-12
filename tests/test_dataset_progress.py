"""Progress chỉ hiển thị endpoint dự kiến; không làm traffic hay ghi dataset."""
import contextlib
import io
import json
import threading
from types import SimpleNamespace
import unittest

from src.data_generation.runtime import DatasetProgress, case_endpoints
from scripts.run_dataset_campaign import ROOT


class DatasetProgressTests(unittest.TestCase):
    def setUp(self):
        self.roles = json.loads((ROOT / "experiments/lab_roles.json").read_text())["roles"]

    def test_tls_and_scan_targets(self):
        route = case_endpoints("tls_weak_cipher", self.roles, "lab-v3-attacks")
        self.assertIn("client(172.30.10.10)", route)
        self.assertIn("proxy(172.30.20.10):4443", route)
        scan = case_endpoints("nmap_ssh_horizontal_scan", self.roles, "lab-v3-attacks")
        self.assertIn("backend(172.30.30.20):22", scan)
        self.assertIn("db(172.30.30.30):22", scan)

    def test_case_metadata_without_configuration_or_credentials(self):
        harness = SimpleNamespace(config={"collection_profile": "lab-v3-attacks", "password": "DO_NOT_PRINT_SECRET"},
            lock=threading.Lock(), background_counts={}, background_failures={})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            reporter = DatasetProgress(harness, True)
            try:
                reporter.case("ssh_password_guessing")
            finally:
                reporter.close()
        result = output.getvalue()
        self.assertIn("CASE START ssh_password_guessing", result)
        self.assertIn("bastion(172.30.20.20):2223", result)
        self.assertIn("label=attack_behavior", result)
        self.assertNotIn("DO_NOT_PRINT_SECRET", result)

    def test_disabled_progress_is_silent(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            reporter = DatasetProgress(None)
            reporter.phase("PREPARE")
            reporter.case("tls_weak_cipher")
            reporter.close()
        self.assertEqual(output.getvalue(), "")
