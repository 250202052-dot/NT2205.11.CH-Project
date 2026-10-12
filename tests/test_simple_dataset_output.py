"""Kiểm tra CSV gọn, mapping nhãn và resume; không tạo traffic Docker."""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.data_generation.generator import Harness, write_manifest
from scripts.run_dataset_campaign import ROOT, collect
from src.data_generation.output import publish_csv
from src.features.label_sessions import dataset_types, write_schema, write_tables, FEATURE_VERSION, LABEL_VERSION
from src.features.training_dataset import export_campaign


class SimpleDatasetTests(unittest.TestCase):
    def setup_dataset(self, base):
        output = base / "campaign"
        dataset = output / ".internal/dataset"
        dataset.mkdir(parents=True)
        artifact = output / ".internal/rounds/fixture"
        artifact.mkdir(parents=True)
        manifest = artifact / "manifests/scenario_manifest.csv"
        write_manifest(manifest, [dict(scenario_id="normal", start_time=100, end_time=110,
            src_role="client", dst_role="proxy", protocol="tls", expected_rule="",
            ground_truth_label="benign", expected_behavior="authorized_background")])
        (artifact / "run_status.json").write_text(json.dumps({"manifest": str(manifest)}))
        row = dict.fromkeys(dataset_types(), "")
        row.update(uid="u1", run_id="fixture", scenario_id="fixture_normal", timestamp_unix="101",
            timestamp_utc=datetime.fromtimestamp(101, timezone.utc).isoformat(),
            application_protocol="tls", transport_protocol="tcp", src_ip="172.30.10.10",
            dst_ip="172.30.20.10", src_port="50000", dst_port="443", duration_seconds="1",
            ground_truth_label="benign", src_role="client", dst_role="proxy", feature_version=FEATURE_VERSION,
            label_version=LABEL_VERSION, label_status="matched", expected_behavior="authorized_background")
        write_tables(dataset, [row], [], False)
        write_schema(dataset)
        export_campaign(dataset, base / "private/key", simple_output=True)
        state = {"runs": [{"run_id": "fixture", "artifact": str(artifact), "status": "complete"}]}
        return output, dataset, state, manifest

    def test_public_csv_no_duplicate_on_resume_no_extra_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            output, dataset, state, _ = self.setup_dataset(Path(directory))
            publish_csv(state, output, dataset)
            publish_csv(state, output, dataset)
            self.assertEqual({p.name for p in output.iterdir()}, {"dataset.csv", "scenario_manifest.csv", ".internal"})
            with (output / "dataset.csv").open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["scenario_id"], "fixture_normal")
            self.assertEqual(rows[0]["ground_truth_label"], "benign")
            self.assertNotIn("src_ip", rows[0])
            for folder in ("sample", "splits", "missing_feature_test"):
                self.assertFalse((dataset / "training" / folder).exists())

    def test_wrong_manifest_label_cannot_replace_public_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            output, dataset, state, manifest = self.setup_dataset(Path(directory))
            publish_csv(state, output, dataset)
            before = (output / "dataset.csv").read_bytes()
            manifest.write_text(manifest.read_text().replace("benign", "attack_behavior"))
            with self.assertRaises(ValueError):
                publish_csv(state, output, dataset)
            self.assertEqual((output / "dataset.csv").read_bytes(), before)

    def test_simple_round_locations_callback_and_one_manifest(self):
        config = json.loads((ROOT / "experiments/campaign_attack_v3.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            internal = Path(directory) / ".internal"
            internal.mkdir()
            state = dict(campaign_id="test", mode="flexible", start_date="2099-01-01", config=config,
                         runs=[], simple_output=True)
            callback = Mock()
            with patch("scripts.run_dataset_campaign.generate") as generate, patch("scripts.run_dataset_campaign.read_runs", return_value=([], [])):
                collect(state, internal / "checkpoint.json", max_runs=1, on_round=callback)
            callback.assert_called_once()
            self.assertTrue(generate.call_args.args[0]["single_manifest"])
            self.assertEqual(generate.call_args.kwargs["artifact_directory"].parent, internal / "rounds")
            harness = Harness(generate.call_args.args[0], internal, internal / "manifests")
            harness.write_scenario_manifest({"scenario_id": "normal"})
            self.assertFalse((internal / "manifests/normal").exists())


if __name__ == "__main__":
    unittest.main()
