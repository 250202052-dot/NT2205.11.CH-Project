"""Fixture nhỏ để kiểm tra mapping, sampling, split và chống leakage."""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.audit_custom_dataset import audit, save_json, write_csv
from scripts.prepare_custom_ablation import allocate, prepare
from scripts.run_ablation import feature_groups, load_data, ROOT
from src.features.ablation_training import enrich_packet_vector
from src.features.label_sessions import dataset_types, write_tables, write_schema, checksum, FEATURE_VERSION, LABEL_VERSION
from src.features.training_dataset import training_rows, write_export


def campaign_fixture(folder):
    data = folder / ".internal/dataset"
    data.mkdir(parents=True)
    rows, windows, records, config_days = [], [], [], []
    labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
    for day in range(1, 6):
        run = f"run{day}"
        records.append(dict(run_id=run, day=day, status="complete"))
        config_days.append(dict(day=day, targets={label: 1 for label in labels}))
        for index, label in enumerate(labels):
            ts = 1700000000 + day * 100 + index * 10
            sid = f"{run}_case{index}"
            row = dict.fromkeys(dataset_types(), "")
            row.update(uid=f"u{day}_{index}", run_id=run, scenario_id=sid, timestamp_unix=str(ts),
                timestamp_utc=datetime.fromtimestamp(ts, timezone.utc).isoformat(), application_protocol="tls",
                transport_protocol="tcp", src_ip="172.30.10.10", dst_ip="172.30.20.10", src_port="50000",
                dst_port="443", duration_seconds="1", src_role="client", dst_role="proxy", ground_truth_label=label,
                expected_behavior=f"case{index}", feature_version=FEATURE_VERSION, label_version=LABEL_VERSION, label_status="matched")
            rows.append(row)
            windows.append(dict(run_id=run, scenario_id=sid, start_time=ts-1, end_time=ts+3,
                src_role="client", dst_role="proxy", protocol="tls", dst_port="443", expected_rule="", ground_truth_label=label))
    write_tables(data, rows, []); write_schema(data)
    write_export(data / "training", training_rows(rows, rows, {}, b"a"*32))
    shutil.copyfile(data / "training/labeled_sessions.csv", folder / "dataset.csv")
    write_csv(folder / "scenario_manifest.csv", list(windows[0]), windows)
    save_json(folder / ".internal/public_checksums.json", {name: checksum(folder / name) for name in ("dataset.csv", "scenario_manifest.csv")})
    save_json(data / "checksums.json", {"labeled_sessions.csv": checksum(data / "labeled_sessions.csv")})
    save_json(data / "campaign_summary.json", {"quota_complete": True})
    save_json(folder / ".internal/checkpoint.json", dict(campaign_id="fixture", mode="flexible", runs=records, config={"days": config_days}))


class CustomAuditAblationTests(unittest.TestCase):
    def test_audit_prepare_and_three_feature_groups(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "campaign"
            campaign_fixture(folder)
            report = audit(folder, root / "audit")
            self.assertTrue(report["passed"])
            result = prepare(folder, root / "audit/audit.json", root / "prepared")
            self.assertEqual(result["rows"], 20)
            config = json.loads((ROOT / "experiments/ablation_custom_config.json").read_text())
            splits, _ = load_data(root / "prepared", config)
            self.assertEqual({key: len(rows) for key, rows in splits.items()}, dict(train=12, validation=4, test=4))
            spec = json.loads((ROOT / "experiments/ablation_features_training_v2.json").read_text())
            groups = feature_groups(spec)
            self.assertEqual(groups["C"]["numeric"], groups["A"]["numeric"]+groups["B"]["numeric"])
            spec["groups"]["B"]["categorical"].append("attack_family")
            with self.assertRaises(ValueError):
                feature_groups(spec)

    def test_wrong_ground_truth_is_detected_even_if_checksums_refreshed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "campaign"
            campaign_fixture(folder)
            path = folder / "scenario_manifest.csv"
            content = path.read_text(encoding="utf-8-sig")
            path.write_text(content.replace("benign", "attack_behavior", 1), encoding="utf-8-sig")
            hashes = json.loads((folder / ".internal/public_checksums.json").read_text())
            hashes["scenario_manifest.csv"] = checksum(path)
            save_json(folder / ".internal/public_checksums.json", hashes)
            report = audit(folder, root / "audit")
            self.assertFalse(report["passed"])
            self.assertEqual(sum(report["manifest_errors"].values()), 1)

    def test_allocation_and_packet_summary(self):
        counts = {("tls", "healthcheck"): 2, ("tls", "normal"): 100, ("ssh", "normal"): 50}
        result = allocate(counts, 30)
        self.assertEqual(sum(result.values()), 30)
        self.assertTrue(all(1 <= result[key] <= counts[key] for key in counts))
        row = enrich_packet_vector({"pkt_size_vector": "[100,200]", "tcp_flags_orig": "[1,2,0,0,3,0,0,0]"})
        self.assertEqual(row["packet_size_mean"], 150)
        self.assertEqual(row["tcp_orig_syn"], 2)
        self.assertIsNone(row["tcp_resp_syn"])


if __name__ == "__main__":
    unittest.main()
