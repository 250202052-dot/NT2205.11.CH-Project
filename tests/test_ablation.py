"""Kiểm thử leakage, window và pipeline bằng fixture giả, không tạo traffic.

Chạy: .venv/Scripts/python.exe tests/test_ablation.py
Fixture chỉ phục vụ kiểm thử code, không được dùng làm kết quả nghiên cứu.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.features.flow_context import enrich_flows
from src.features.label_sessions import write_tables, write_schema, checksum, FEATURE_VERSION, LABEL_VERSION
from src.features.build_sessions import CSV_COLUMNS
from src.features.label_sessions import DERIVED_COLUMNS, LABEL_COLUMNS
from scripts.run_ablation import feature_groups, load_data, read_csv
from src.models.ablation import run_ablation, train
from src.models.baselines import training_config, get_feature_groups


def fixture_dataset(directory):
    """Ba split có đủ bốn lớp, timestamp theo thứ tự, run không giao nhau."""
    labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
    master = []
    for block, split in enumerate(("train", "validation", "test")):
        rows = []
        for index in range(16):
            ts = 1700000000 + block * 1000 + index
            row = dict.fromkeys(CSV_COLUMNS + DERIVED_COLUMNS + LABEL_COLUMNS, "")
            row.update(uid=f"C{block}_{index}", run_id=f"run_{block}", scenario_id=f"scenario_{block}_{index}",
                       timestamp_unix=str(ts), timestamp_utc=datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                       src_ip="172.30.10.10", dst_ip="172.30.20.10", src_port="45000", dst_port="443",
                       application_protocol="tls", transport_protocol="tcp", duration_seconds="2",
                       src_bytes="100", dst_bytes="200", src_packets="2", dst_packets="3", connection_state="SF",
                       ground_truth_label=labels[index % 4], tls_version="TLSv12",
                       # Test có categorical mới để kiểm tra handle_unknown.
                       tls_cipher=f"TEST_CIPHER_{index % 4}" if split != "test" else "UNSEEN_CIPHER",
                       feature_version=FEATURE_VERSION, label_version=LABEL_VERSION)
            rows.append(row)
        folder = directory / "splits" / split
        folder.mkdir(parents=True)
        write_tables(folder, rows, [], parquet=False)
        write_schema(folder)
        master.extend(rows)
    write_tables(directory, master, [], parquet=False)
    write_schema(directory)
    full = directory / "full_collection"
    full.mkdir()
    write_tables(full, master, [], parquet=False)
    write_schema(full)
    (directory / "campaign_summary.json").write_text(json.dumps({
        "campaign_id": "synthetic_test_only", "clock_mode": "compressed", "quota_complete": True
    }))
    refresh_checksums(directory)


def refresh_checksums(directory):
    (directory / "checksums.json").write_text(json.dumps({str(p.relative_to(directory)): checksum(p)
        for p in directory.rglob("*") if p.is_file() and p.name != "checksums.json"}))


class AblationTests(unittest.TestCase):
    def test_flow_zero_missing_window_and_run_reset(self):
        base = dict(src_ip="172.30.10.10", dst_ip="172.30.20.10", dst_port="443",
                    src_bytes="10", dst_bytes="20", src_packets="1", dst_packets="2", duration_seconds="0")
        rows = [dict(base, run_id="r1", uid="C1", timestamp_unix="100"),
                dict(base, run_id="r1", uid="C2", timestamp_unix="110"),
                dict(base, run_id="r1", uid="C3", timestamp_unix="161"),
                dict(base, run_id="r2", uid="C4", timestamp_unix="162", dst_bytes="")]
        enriched = enrich_flows(rows)
        self.assertIsNone(enriched[0]["flow_bytes_per_second"])
        self.assertEqual(enriched[0]["flow_source_connections_10s"], 1)  # Không nhìn C2 trong tương lai.
        self.assertEqual(enriched[1]["flow_source_connections_10s"], 2)  # Biên 10s được tính.
        self.assertEqual(enriched[2]["flow_source_connections_60s"], 2)
        self.assertEqual(enriched[3]["flow_source_connections_60s"], 1)  # Reset run.
        self.assertIsNone(enriched[3]["flow_total_bytes"])
        self.assertNotIn("flow_total_bytes", rows[0])  # Không sửa nguồn.

    def test_feature_union_and_leakage_rejection(self):
        spec = json.loads((ROOT / "tests/fixtures/legacy_configs/ablation_features.json").read_text())
        groups = feature_groups(spec)
        self.assertIn("ssh_ja4ssh", groups["B"]["categorical"])
        self.assertNotIn("ssh_ja4ssh", groups["A"]["categorical"])
        self.assertEqual(groups["C"]["numeric"], groups["A"]["numeric"] + groups["B"]["numeric"])
        spec["groups"]["B"]["categorical"].append("tls_policy_violations")
        with self.assertRaises(ValueError):
            feature_groups(spec)

    def test_audit_checksum_and_required_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture_dataset(directory)
            config = json.loads((ROOT / "tests/fixtures/legacy_configs/ablation_config.json").read_text())
            splits, _ = load_data(directory, config)
            self.assertEqual(len(splits["test"]), 16)
            # Thay source dù chỉ thêm newline cũng phải bị checksum chặn.
            with (directory / "labeled_sessions.csv").open("a") as handle:
                handle.write("\n")
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_data(directory, config)

    def test_three_experiments_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "dataset"
            directory.mkdir()
            fixture_dataset(directory)
            config = json.loads((ROOT / "tests/fixtures/legacy_configs/ablation_config.json").read_text())
            config.update(dataset_directory=str(directory), feature_config=str(ROOT / "tests/fixtures/legacy_configs/ablation_features.json"),
                          output_directory=str(Path(temporary) / "results"), seeds=[42], cv_splits=0)
            config["model"]["n_estimators"] = 8
            config_path = Path(temporary) / "config.json"
            config_path.write_text(json.dumps(config))
            process = subprocess.run([sys.executable, str(ROOT / "scripts/run_ablation.py"), "--config", str(config_path), "--train"],
                                     capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            output = next((Path(temporary) / "results").iterdir())
            self.assertEqual(output.name, "ketqua_lan1")
            self.assertEqual(sorted(p.name for p in output.iterdir()), ["summary.csv"])
            rows = read_csv(output / "summary.csv")
            self.assertEqual([r["feature_group"] for r in rows], ["A", "B", "C"])
            self.assertTrue(all(r["model"] == "random_forest" for r in rows))
            self.assertEqual(list(rows[0]), ["feature_group", "model", "accuracy_mean",
                "recall_macro_mean", "macro_f1_mean", "mcc_mean", "ap_attack_mean", "tpr_attack_mean", "fpr_attack_mean",
                "train_seconds_mean", "predict_seconds_mean"])
            # Audit dùng cùng config nhưng không tạo thêm output.
            audit = subprocess.run([sys.executable, str(ROOT / "scripts/run_ablation.py"),
                                    "--config", str(config_path)], capture_output=True, text=True)
            self.assertEqual(audit.returncode, 0, audit.stdout + audit.stderr)
            self.assertEqual([p.name for p in output.parent.iterdir()], ["ketqua_lan1"])

    def test_shared_run_rejected_even_with_updated_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture_dataset(directory)
            config = json.loads((ROOT / "tests/fixtures/legacy_configs/ablation_config.json").read_text())
            # Giả lập lỗi chia cùng một run vào cả train và validation.
            for folder in (directory, directory / "full_collection", directory / "splits/validation"):
                rows = read_csv(folder / "labeled_sessions.csv")
                for row in rows:
                    if row["run_id"] == "run_1":
                        row["run_id"] = "run_0"
                write_tables(folder, rows, [], parquet=False)
            refresh_checksums(directory)
            with self.assertRaisesRegex(ValueError, "shared run"):
                load_data(directory, config)

    def test_default_ablation_uses_baseline_features_parameters_and_training(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            splits = {"train": [], "validation": [], "test": []}
            with patch("src.models.ablation.load_data", return_value=(splits, {})) as reader, \
                 patch("src.models.ablation.new_result_folder", return_value=output), \
                 patch("src.models.baselines.train_models", return_value=[]) as trainer:
                run_ablation(train_models=True)
            self.assertEqual(reader.call_args.args[1], training_config())
            trainer.assert_called_once_with(splits, get_feature_groups(), training_config(), output)
            self.assertEqual(training_config()["seeds"], [42])
            self.assertEqual(training_config()["cv_splits"], 3)
            self.assertEqual(list(training_config()["models"]), ["random_forest", "xgboost", "lightgbm"])


if __name__ == "__main__":
    unittest.main()
