"""Kiểm thử timeout/retry bằng mock; không tạo traffic hay sửa dataset."""
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.data_generation import runtime as lab_runtime
from src.data_generation.generator import Harness


class TimeoutTests(unittest.TestCase):
    def harness(self):
        return Harness({"seed": 1}, ROOT, ROOT)

    def test_timeout_is_not_public_key_rejection(self):
        harness = self.harness()
        with patch("src.data_generation.generator.exec_lab", return_value=subprocess.CompletedProcess([], 137, b"", b"")), patch("src.data_generation.generator.time.sleep"):
            with self.assertRaisesRegex(RuntimeError, "3 bounded attempts"):
                harness.ssh_action("ssh_bruteforce_like")
        self.assertEqual(harness.ssh_timeouts["ssh_bruteforce_like"], 3)

    def test_retry_then_verified_rejection(self):
        harness = self.harness()
        results = [lab_runtime.LabCommandTimeout("timeout"), subprocess.CompletedProcess([], 255, b"", b"Permission denied (publickey)")]
        with patch("src.data_generation.generator.exec_lab", side_effect=results) as execute, patch("src.data_generation.generator.time.sleep"):
            result = harness.ssh_action("ssh_bruteforce_like")
        self.assertEqual(result.returncode, 255)
        self.assertEqual(execute.call_args.args[1:5], ("timeout", "-s", "KILL", "15"))
        self.assertEqual(execute.call_args.kwargs["timeout"], 30)

    def test_wrong_failure_is_not_retried_or_labeled(self):
        with patch("src.data_generation.generator.exec_lab", return_value=subprocess.CompletedProcess([], 255, b"", b"Host key verification failed")) as execute:
            with self.assertRaisesRegex(RuntimeError, "expected public-key rejection"):
                self.harness().ssh_action("ssh_bruteforce_like")
        self.assertEqual(execute.call_count, 1)

    def test_docker_error_hides_arguments_and_output(self):
        with patch("src.data_generation.runtime.subprocess.run", side_effect=subprocess.TimeoutExpired(["SECRET_ARG"], 10, output=b"SECRET_OUTPUT")):
            with self.assertRaises(lab_runtime.LabCommandTimeout) as error:
                lab_runtime.docker("compose", timeout=10)
        self.assertNotIn("SECRET", str(error.exception))


if __name__ == "__main__":
    unittest.main()
