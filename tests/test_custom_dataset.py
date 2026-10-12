"""Regression tests for time/role labeling, metadata-only exports and checksums."""
import csv
from contextlib import redirect_stdout
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.features.label_sessions import assign_label, load_manifest, label_dataset, checksum
from src.data_generation.generator import write_manifest, validate_config

spec = importlib.util.spec_from_file_location("privacy", ROOT / "data/schemas/validate_zeek_metadata.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class DatasetTests(unittest.TestCase):
    def test_combined_dataset_tools_dispatch(self):
        from scripts.dataset_tools import main
        cases = [
            (["training", "--dataset", "fixture", "--parquet"], "export_campaign"),
            (["extended", "--run", "fixture", "--parquet"], "export_run"),
            (["extended", "--validate", "fixture"], "validate_companion"),
        ]
        for arguments, function in cases:
            with self.subTest(command=arguments), patch("sys.argv", ["dataset_tools.py", *arguments]), \
                 patch(f"scripts.dataset_tools.{function}", return_value={"passed": True}) as action, \
                 redirect_stdout(io.StringIO()):
                main()
                self.assertEqual(action.call_args.args[0], Path("fixture"))
                action.assert_called_once()

    def setUp(self):
        self.roles = json.loads((ROOT / "experiments/lab_roles.json").read_text())
        self.window = dict(scenario_id="fixture", start=100.0, end=110.0, src_role="client", dst_role="proxy",
                           protocol="tls", expected_rule="TLS_RSA_KEY_TOO_SMALL", ground_truth_label="misconfiguration", dst_port="443")
        self.session = dict(uid="uid1", timestamp_unix="101", duration_seconds="1", src_ip="172.30.10.10",
                            dst_ip="172.30.20.10", dst_port="443", application_protocol="tls", transport_protocol="tcp")

    def test_time_boundaries_and_unmatched_are_not_benign(self):
        self.assertEqual(assign_label(self.session, [self.window], self.roles)[0]["ground_truth_label"], "misconfiguration")
        self.assertEqual(assign_label(dict(self.session, timestamp_unix="110"), [self.window], self.roles)[1], "unmatched")
        self.assertEqual(assign_label(dict(self.session, timestamp_unix="109", duration_seconds="2"), [self.window], self.roles)[1], "boundary_overlap")
        self.assertEqual(assign_label(dict(self.session, dst_ip="172.30.30.20"), [self.window], self.roles)[1], "unmatched")

    def test_uid_selector_and_ambiguity(self):
        self.assertEqual(assign_label(self.session, [self.window, dict(self.window, scenario_id="other")], self.roles)[1], "ambiguous_manifest")
        self.assertEqual(assign_label(self.session, [dict(self.window, session_uids="different")], self.roles)[1], "unmatched")

    def test_nat_context_is_required(self):
        window = dict(self.window, src_role="bastion", dst_role="backend", protocol="ssh", dst_port="22")
        session = dict(self.session, src_ip="172.30.30.254", dst_ip="172.30.30.20", dst_port="22", application_protocol="ssh")
        self.assertEqual(assign_label(session, [window], self.roles)[0]["src_role"], "bastion")
        self.assertEqual(assign_label(dict(session, dst_port="8000"), [window], self.roles)[2][0], "unknown")

    def test_manifest_rejects_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = {key: self.window.get(key, "") for key in ("scenario_id", "src_role", "dst_role", "protocol", "expected_rule", "ground_truth_label", "dst_port")}
            row.update(start_time=100, end_time=110, expected_behavior="weak_key", scenario_type="abnormal", completed="false")
            path = Path(tmp) / "scenario_manifest.csv"
            write_manifest(path, [row])
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_export_uses_manifest_not_alert_as_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "zeek"
            logs.mkdir()
            records = [dict(ts=101, uid="weakTLS", **{"id.orig_h": "172.30.10.10", "id.orig_p": 40001,
                "id.resp_h": "172.30.20.10", "id.resp_p": 443, "proto": "tcp", "duration": 1}),
                dict(ts=101, uid="benignSSH", **{"id.orig_h": "172.30.10.10", "id.orig_p": 40002,
                "id.resp_h": "172.30.20.20", "id.resp_p": 2222, "proto": "tcp", "duration": 1}),
                dict(ts=120, uid="unmatched", **{"id.orig_h": "192.0.2.1", "id.orig_p": 40003,
                "id.resp_h": "172.30.20.10", "id.resp_p": 443, "proto": "tcp", "duration": 1})]
            (logs / "conn.log").write_text("\n".join(json.dumps(r) for r in records))
            ssl = {k: v for k, v in records[0].items() if k.startswith("id.") or k in {"ts", "uid"}}
            ssl.update(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", established=True,
                       policy_violations=[], cert_chain_fps=[])
            (logs / "ssl.log").write_text(json.dumps(ssl))
            (logs / "tls_extensions.log").write_text(json.dumps({"ts": 101, "uid": "weakTLS",
                "metadata_version": "tls-extensions-v1", "client_hello_observed": True,
                "server_hello_observed": False, "client_extensions": [13], "server_extensions": [], "ech_observed": False}))
            ssh = {k: v for k, v in records[1].items() if k.startswith("id.") or k in {"ts", "uid"}}
            # A false-positive detector alert must not change known benign label.
            ssh.update(version=2, policy_violations=["SSH_KEX_WEAK"])
            (logs / "ssh.log").write_text(json.dumps(ssh))
            manifest = root / "scenario_manifest.csv"
            rows = [dict(scenario_id="weak_key", start_time=100, end_time=110, src_role="client", dst_role="proxy",
                         protocol="tls", expected_rule="TLS_RSA_KEY_TOO_SMALL", expected_behavior="weak_key",
                         ground_truth_label="misconfiguration", dst_port=443, scenario_type="abnormal", completed="true"),
                    dict(scenario_id="normal", start_time=100, end_time=110, src_role="client", dst_role="bastion",
                         protocol="ssh", expected_rule="", expected_behavior="authorized", ground_truth_label="benign",
                         dst_port=2222, scenario_type="background", completed="true")]
            write_manifest(manifest, rows)
            output = root / "output"
            parquet = importlib.util.find_spec("pyarrow") is not None
            summary = label_dataset(logs, manifest, ROOT / "experiments/lab_roles.json", output, "test", parquet)
            with (output / "labeled_sessions.csv").open(encoding="utf-8-sig") as handle:
                labeled = list(csv.DictReader(handle))
            self.assertEqual({r["uid"]: r["ground_truth_label"] for r in labeled}, {"weakTLS": "misconfiguration", "benignSSH": "benign"})
            self.assertEqual(summary["quarantined_count"], 1)
            self.assertEqual(summary["extended_metadata"]["tls_extension_rows"], 1)
            self.assertEqual(summary["extended_metadata"]["rows"], 2)
            self.assertEqual(next(r for r in labeled if r["uid"] == "weakTLS")["expected_rule_observed"], "false")
            for name, digest in summary["checksums"].items():
                self.assertEqual(checksum(output / name), digest)
            privacy.validate_dataset(output)
            path = output / "labeled_sessions.csv"
            with path.open(encoding="utf-8-sig") as handle:
                original = handle.read()
            path.write_text(original.replace("uid,", "http.body,", 1), encoding="utf-8-sig")
            with self.assertRaises(ValueError):
                privacy.validate_dataset(output)
            path.write_text(original.replace("weakTLS", "PRIVATE_PAYLOAD_MARKER"), encoding="utf-8-sig")
            with self.assertRaises(ValueError):
                privacy.validate_dataset(output)


if __name__ == "__main__":
    unittest.main()
