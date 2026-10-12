"""v2 regression: flexible collection, causal features and privacy-safe export.

Fixtures stay in temporary directories. No Docker traffic, no campaign changes.
"""
import csv
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
from scripts.run_dataset_campaign import collect, make_run_config, validate_campaign
from src.data_generation.scenarios import DatasetHarnessV2
from src.features.label_sessions import dataset_types, write_tables, write_schema, FEATURE_VERSION, LABEL_VERSION
from src.features.training_dataset import training_rows, historical_features, write_export, export_campaign, schema
from data.schemas.validate_zeek_metadata import validate_dataset


def fixture(uid, ts, **extra):
    row = dict.fromkeys(dataset_types(), "")
    row.update(uid=uid, run_id="fixture", scenario_id="normal", timestamp_unix=str(ts),
        timestamp_utc=datetime.fromtimestamp(ts, timezone.utc).isoformat(), application_protocol="tls", transport_protocol="tcp",
        src_ip="172.30.10.10", dst_ip="172.30.20.10", src_port="50000", dst_port="4443", duration_seconds="1",
        ground_truth_label="benign", src_role="client", dst_role="proxy", feature_version=FEATURE_VERSION,
        label_version=LABEL_VERSION, label_status="matched", expected_behavior="authorized_background")
    row.update(extra)
    return row


class DatasetV2Tests(unittest.TestCase):
    def test_stale_sensor_image_rejected_before_changing_lab(self):
        config = json.loads((ROOT / "tests/fixtures/legacy_configs/custom_dataset_v2.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            harness = DatasetHarnessV2(config, Path(temporary), Path(temporary) / "manifests")
            replies = [subprocess.CompletedProcess([], 1, b"", b""),
                       subprocess.CompletedProcess([], 0, b"true\n", b""),
                       subprocess.CompletedProcess([], 0, b"1 zeek -b -i mirror0 /config/local.zeek\n", b"")]
            with patch("src.data_generation.scenarios.exec_lab", side_effect=replies), patch("src.data_generation.generator.Harness.prepare") as prepare:
                with self.assertRaisesRegex(ValueError, "image is stale"):
                    harness.prepare()
                prepare.assert_not_called()

    def test_new_config_and_legacy_are_separate(self):
        config = json.loads((ROOT / "tests/fixtures/legacy_configs/campaign_flexible_v2.json").read_text())
        validate_campaign(config)
        self.assertEqual(config["slots"], ["batch_1"])
        self.assertEqual(sum(sum(d["targets"].values()) for d in config["days"]), 20000)
        run = make_run_config(config, 2, 0, 0, config["days"][1]["targets"])
        self.assertEqual(run["collection_profile"], "lab-v2")
        self.assertIn("l3_scan_burst", run["scenarios"])
        old = json.loads((ROOT / "tests/fixtures/legacy_configs/campaign_20k.json").read_text())
        legacy = make_run_config(old, 2, 0, 0, old["days"][1]["targets"])
        self.assertNotIn("l3_scan_burst", legacy["scenarios"])

    def test_flexible_runs_immediately_and_stops_after_one_round(self):
        config = json.loads((ROOT / "tests/fixtures/legacy_configs/campaign_flexible_v2.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            state = dict(campaign_id="test", mode="flexible", start_date="2099-01-01", config=config, runs=[])
            with patch("scripts.run_dataset_campaign.generate") as generate, patch("scripts.run_dataset_campaign.read_runs", return_value=([], [])), patch("scripts.run_dataset_campaign.wait_until") as wait:
                collect(state, Path(temporary) / "checkpoint.json", max_runs=1)
            generate.assert_called_once()
            wait.assert_not_called()
            self.assertEqual(state["runs"][0]["status"], "complete")
            self.assertIn("actual_end_utc", state["runs"][0])

    def test_history_no_future_identity_no_equal_time_leakage(self):
        rows = [fixture("long", 100, duration_seconds="30", cert_spki_sha256="a" * 64, tls_ja4="new"),
            fixture("same", 100), fixture("early", 105, cert_spki_sha256="b" * 64, tls_ja4="new"),
            fixture("later", 140, cert_spki_sha256="b" * 64, tls_ja4="new"), fixture("other_run", 145, run_id="next")]
        history = historical_features(rows)
        self.assertEqual(history[("fixture", "same")]["session_rate_5m"], 0)
        self.assertIsNone(history[("fixture", "early")]["certificate_identity_changed"])
        self.assertTrue(history[("fixture", "later")]["certificate_identity_changed"])
        self.assertIsNone(history[("fixture", "early")]["baseline_fp_prevalence"])
        self.assertEqual(history[("next", "other_run")]["new_edge_score"], 1)

    def test_training_csv_parquet_validator_and_raw_field_rejection(self):
        rows = training_rows([fixture("u1", 101), fixture("u2", 103)], [fixture("u1", 101), fixture("u2", 103)], {}, b"a" * 32)
        self.assertNotIn("src_ip", rows[0])
        self.assertEqual(rows[0]["src_host_token"], rows[1]["src_host_token"])
        self.assertFalse(rows[0]["packet_metadata_present"])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            write_export(output, rows, parquet=True)
            self.assertTrue(validate_dataset(output)["passed"])
            path = output / "labeled_sessions.csv"
            original = path.read_text(encoding="utf-8-sig")
            path.write_text(original.replace("src_host_token", "http.body", 1), encoding="utf-8-sig")
            with self.assertRaises(ValueError):
                validate_dataset(output)

    def test_complete_export_and_missingness_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "dataset"
            source.mkdir()
            write_tables(source, [fixture("u1", 101)], [], parquet=True)
            write_schema(source)
            key = Path(temporary) / "private/key"
            report = export_campaign(source, key, parquet=True)
            self.assertEqual(report["rows"], 1)
            self.assertTrue((source / "training/sample/labeled_sessions.parquet").exists())
            self.assertFalse(json.loads((source / "training/missing_feature_test/condition.json").read_text())["actual_ech_capture"])
            self.assertFalse(any(p.name == "key" for p in source.rglob("*")))

    def test_tls_v2_does_not_pause_modern_background(self):
        config = json.loads((ROOT / "tests/fixtures/legacy_configs/custom_dataset_v2.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = DatasetHarnessV2(config, root, root / "manifests")
            with patch.object(harness, "tls_fixture"), patch.object(harness, "tls_request"), patch.object(harness, "pause_tls_background") as pause, patch("src.data_generation.scenarios.exec_lab", return_value=subprocess.CompletedProcess([], 0, b"certificate", b"")), patch("src.data_generation.scenarios.time.monotonic", side_effect=[0, 100]):
                harness.run_scenario("tls_weak_cipher")
            pause.assert_not_called()
            self.assertEqual(harness.rows[0]["dst_port"], 4443)
            self.assertEqual(harness.rows[0]["completed"], "true")


if __name__ == "__main__":
    unittest.main()
