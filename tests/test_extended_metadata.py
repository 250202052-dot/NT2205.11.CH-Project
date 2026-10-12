"""Kiểm thử log mở rộng và companion; không restart sensor/campaign."""
import copy
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data.schemas.validate_zeek_metadata import validate
from data.schemas.validate_extended_metadata import validate_record
from src.features.build_sessions import read_log_index
from src.features.extended_metadata import companion_rows, raw_indices, write_companion, validate_companion


class ExtendedTests(unittest.TestCase):
    def test_zeek_events_and_companion_parquet(self):
        # Đồng bộ stream allowlist với các field thực sự được xuất bởi profile.
        spec = json.loads((ROOT / "data/schemas/zeek_metadata_allowlist.json").read_text())
        script = (ROOT / "sensors/zeek/extended_profile.zeek").read_text()
        for module, stream in (("PacketMetadata", "packet_metadata"), ("TLSExtensions", "tls_extensions")):
            fields = re.findall(r'"([^"]+)"', re.search(r'\[' + module + r'::LOG\]\s*=\s*set\((.*?)\)', script, re.S)[1])
            self.assertEqual(set(fields), set(spec["streams"][stream]))
        with tempfile.TemporaryDirectory() as temporary:
            logs = Path(temporary)
            args = ["docker", "run", "--rm", "--network", "none",
                    "--mount", f"type=bind,source={ROOT / 'sensors/zeek'},target=/config,readonly",
                    "--mount", f"type=bind,source={ROOT / 'tests/zeek'},target=/tests,readonly",
                    "--mount", f"type=bind,source={logs},target=/output", "--workdir", "/output",
                    "--entrypoint", "zeek", "topic4-zeek", "-b", "/config/local.zeek", "/config/extended_profile.zeek", "/tests/extended_cases.zeek"]
            process = subprocess.run(args, capture_output=True, text=True, timeout=45)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            counts = validate(logs)
            self.assertEqual(counts["packet_metadata"], 1)
            self.assertEqual(counts["tls_extensions"], 1)
            for path in logs.glob("*.log"):
                self.assertNotIn("PRIVATE_PAYLOAD_MARKER", path.read_text())
            indices = raw_indices(logs)
            tls = indices["tls_extensions"]["testExtra"]
            self.assertTrue(tls["ech_observed"])
            self.assertEqual(tls["client_signature_schemes"], [2052])
            self.assertEqual(tls["server_signature_scheme"], 1025)
            # Session cũ vẫn giữ thiếu; không tự chuyển thành rate=0/ECH=false.
            rows = companion_rows([{"run_id": "run1", "uid": "testExtra"}, {"run_id": "run1", "uid": "oldSession"}], indices)
            self.assertIsNone(rows[1]["ech_observed"])
            self.assertFalse(rows[1]["packet_metadata_present"])
            output = logs / "extended"
            result = write_companion(output, rows, parquet=True)
            self.assertEqual(result["packet_rows"], 1)
            self.assertTrue(validate_companion(output)["passed"])
            bad = copy.deepcopy(indices["packet_metadata"]["testExtra"])
            bad["pkt_size_vector"] = ["PRIVATE_PAYLOAD_MARKER"]
            with self.assertRaises(ValueError):
                validate_record("packet_metadata", bad)

    def test_missing_hello_truncation_and_malformed_vectors(self):
        tls = {"ts": 1, "uid": "test", "metadata_version": "tls-extensions-v1",
               "client_hello_observed": False, "server_hello_observed": False,
               "client_extensions": [], "server_extensions": []}
        validate_record("tls_extensions", tls)
        tls["ech_observed"] = False
        with self.assertRaises(ValueError):
            validate_record("tls_extensions", tls)
        packet = {"ts": 1, "uid": "test", "metadata_version": "packet-metadata-v1", "sequence_limit": 2,
                  "orig_observed_packets": 3, "resp_observed_packets": 0,
                  "orig_iat_count": 2, "resp_iat_count": 0, "orig_iat_mean": 0.1, "orig_iat_std": 0,
                  "unordered_timestamps": 0, "pkt_size_vector": [60, 52], "pkt_direction_vector": [0, 0], "sequence_truncated": True}
        validate_record("packet_metadata", packet)
        packet["pkt_direction_vector"] = [0, 2]
        with self.assertRaises(ValueError):
            validate_record("packet_metadata", packet)


if __name__ == "__main__":
    unittest.main()
