import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.features.label_sessions import write_tables, write_schema, dataset_types, FEATURE_VERSION, LABEL_VERSION, checksum
from src.features.aggregate_campaign import aggregate, read_runs
from scripts.run_dataset_campaign import slot_targets, make_run_config, validate_campaign, validate_campaign_id


class CampaignTests(unittest.TestCase):
    def test_fixed_campaign_name(self):
        self.assertEqual(validate_campaign_id("20261009_extended_v1"), "20261009_extended_v1")
        for value in ("../outside", "D:\\outside", "", "CON", "test/round"):
            with self.assertRaises(ValueError):
                validate_campaign_id(value)

    def test_quotas_and_benign_day(self):
        config = json.loads((ROOT / "tests/fixtures/legacy_configs/campaign_20k.json").read_text())
        validate_campaign(config)
        self.assertEqual(sum(sum(d["targets"].values()) for d in config["days"]), 20000)
        for day in config["days"]:
            parts = [slot_targets(day, index, 3) for index in range(3)]
            self.assertEqual({label: sum(p[label] for p in parts) for label in day["targets"]}, day["targets"])
        run = make_run_config(config, 1, 0, 0, config["days"][0]["targets"])
        self.assertTrue(run["benign_only"])
        self.assertFalse(run["scenarios"])
        self.assertEqual(run, make_run_config(config, 1, 0, 0, config["days"][0]["targets"]))

    def test_aggregate_no_duplicates_and_shortfall(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "source"
            artifact.mkdir()
            rows = []
            for index, proto in enumerate(["tls", "ssh", ""]):
                row = dict.fromkeys(dataset_types(), "")
                row.update(uid=f"u{index}", run_id="fixture", scenario_id="baseline", timestamp_unix=str(100 + index),
                    timestamp_utc=datetime.fromtimestamp(100 + index, timezone.utc).isoformat(), application_protocol=proto,
                    transport_protocol="tcp", src_ip="172.30.10.10", dst_ip="172.30.20.10", src_port="40000", dst_port="443",
                    ground_truth_label="benign", src_role="client", dst_role="proxy", feature_version=FEATURE_VERSION,
                    label_version=LABEL_VERSION, label_status="matched", expected_behavior="authorized_background", duration_seconds="1")
                rows.append(row)
            write_tables(artifact, rows, [])
            write_schema(artifact)
            (artifact / "run_status.json").write_text(json.dumps({"completed": True, "cleanup_passed": True}))
            (artifact / "checksums.json").write_text(json.dumps({"labeled_sessions.csv": checksum(artifact / "labeled_sessions.csv")}))
            logs = artifact / "zeek"
            logs.mkdir()
            (logs / "tls_extensions.log").write_text(json.dumps({"ts": 100, "uid": "u0",
                "metadata_version": "tls-extensions-v1", "client_hello_observed": True,
                "server_hello_observed": False, "client_extensions": [13], "server_extensions": [], "ech_observed": False}))
            record = dict(status="complete", run_id="fixture", artifact=str(artifact), day=1, slot="09:00", round=0)
            tls_ssh, context = read_runs([record, record])
            self.assertEqual((len(tls_ssh), len(context)), (2, 1))
            state = dict(campaign_id="fixture", mode="compressed", runs=[record], config={"seed": 1,
                "days": [{"day": 1, "targets": {"benign": 3, "misconfiguration": 0, "policy_violation": 0, "attack_behavior": 0}}]})
            report = aggregate(state, root / "output")
            self.assertEqual(report["selected_rows"], 2)
            self.assertEqual(report["shortfalls"], {"day1_benign": 1})
            self.assertFalse(report["quota_complete"])
            self.assertFalse(report["timestamps_modified"])
            self.assertEqual(report["extended_metadata"]["tls_extension_rows"], 1)
            self.assertEqual(report["extended_metadata"]["rows"], 2)
            source = artifact / "labeled_sessions.csv"
            source.write_text(source.read_text(encoding="utf-8-sig").replace("40000", "40001"), encoding="utf-8-sig")
            with self.assertRaisesRegex(ValueError, "checksum"):
                read_runs([record])


if __name__ == "__main__":
    unittest.main()
