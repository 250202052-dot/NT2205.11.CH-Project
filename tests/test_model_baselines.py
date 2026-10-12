"""Kiểm tra ba thư viện chạy được, nhãn được decode đúng và không fit vào test."""
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.models.baselines import (train_models, make_model, new_result_folder, prepare_features,
                                 chronological_folds, cross_validate_models)
from scripts.run_model_baselines import main
from src.models.ablation import metrics


class BaselineTests(unittest.TestCase):
    def test_temporal_cv_keeps_runs_separate_and_refits_three_models(self):
        labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
        rows = [dict(run_id=f"run{run}", timestamp_unix=run * 100 + label * 10,
                     duration_seconds=1, ground_truth_label=labels[label], tls_version=str(label))
                for run in range(12) for label in range(4)]
        folds = chronological_folds(list(reversed(rows)), labels, 3)
        self.assertEqual(len(folds), 3)
        self.assertEqual([len(f['train']) for f in folds], [12, 24, 36])
        for fold in folds:
            self.assertFalse({r['run_id'] for r in fold['train']} & {r['run_id'] for r in fold['validation']})
            self.assertLess(max(r['timestamp_unix'] + 1 for r in fold['train']),
                            min(r['timestamp_unix'] for r in fold['validation']))
        config = dict(labels=labels, n_jobs=1, models={
            "random_forest": dict(n_estimators=2, max_depth=2),
            "xgboost": dict(n_estimators=2, max_depth=2),
            "lightgbm": dict(n_estimators=2, num_leaves=3, min_child_samples=1)})
        group = {"numeric": ["duration_seconds"], "categorical": ["tls_version"]}
        with patch("src.models.baselines.make_model", wraps=make_model) as factory:
            results = cross_validate_models(folds, group, "C", config)
        self.assertEqual(factory.call_count, 9)
        self.assertTrue(all(call.args[2] == 42 for call in factory.call_args_list))
        self.assertTrue(all(len(scores) == 3 for scores in results.values()))
        for row in rows[:12]:
            row['ground_truth_label'] = 'benign'
        with self.assertRaisesRegex(ValueError, 'CV train'):
            chronological_folds(rows, labels, 3)

    def test_multiclass_metrics_and_attack_tpr_fpr(self):
        labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
        truth = [labels[0], labels[0], labels[1], labels[1], labels[2], labels[2], labels[3], labels[3]]
        predicted = [labels[0], labels[3], labels[1], labels[3], labels[2], labels[1], labels[3], labels[0]]
        result = metrics(truth, predicted, labels)
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["macro_recall"], 0.5)
        self.assertEqual(result["tpr_attack"], 0.5)
        self.assertAlmostEqual(result["fpr_attack"], 1 / 3)
        self.assertAlmostEqual(result["macro_f1"], (0.5 + 0.5 + 2 / 3 + 0.4) / 4)
        self.assertEqual(result["benign_false_alarm_rate"], 0.5)
        no_attack = metrics(["benign"], ["benign"], labels)
        self.assertIsNone(no_attack["tpr_attack"])

    def test_preprocessing_uses_train_only_and_preserves_expired_certificate_sign(self):
        import numpy as np
        group = {"numeric": ["src_bytes", "cert_remaining_days_at_session", "cert_key_bits"],
                 "categorical": ["tls_cipher"]}
        def row(size, days, cipher):
            return dict(src_bytes=size, cert_remaining_days_at_session=days,
                        cert_key_bits=None, tls_cipher=cipher)
        splits = {"train": [row(0, -2, " rare "), row(8, 2, "other")],
                  "validation": [row(None, None, "new")],
                  "test": [row(1000000, -8, "new") ]}
        x = prepare_features(splits, group)
        self.assertAlmostEqual(float(x["validation"][0, 0]), np.log1p(8) / 2, places=6)
        self.assertEqual(x["test"][0, 1], -8)
        self.assertEqual(x["validation"][0, 3], 1)  # missing src_bytes
        self.assertEqual(x["train"][0, 5], 1)  # cột cert_key_bits trống hoàn toàn
        self.assertEqual(x["test"].shape[1], x["train"].shape[1])
        self.assertTrue(np.isfinite(x["validation"]).all())
        splits["test"][0]["src_bytes"] = -1
        with self.assertRaises(ValueError):
            prepare_features(splits, group)

    def test_audit_does_not_create_results(self):
        with patch("sys.argv", ["run_model_baselines.py"]), \
             patch("pathlib.Path.is_file", return_value=True), \
             patch("src.models.baselines.load_data", return_value=({}, {})), \
             patch("src.models.baselines.new_result_folder") as create:
            main()
        create.assert_not_called()

    def test_numbered_folders_preserve_existing_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            first = new_result_folder(parent)
            self.assertEqual(first.name, "ketqua_lan1")
            (first / "summary.csv").write_text("keep")
            (parent / "ketqua_lan3").mkdir()
            self.assertEqual(new_result_folder(parent).name, "ketqua_lan4")
            self.assertEqual((first / "summary.csv").read_text(), "keep")

    def test_three_models_end_to_end_and_train_only_preprocessing(self):
        labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
        splits = {}
        for split in ("train", "validation", "test"):
            splits[split] = [dict(run_id=split, uid=str(i), ground_truth_label=labels[i % 4],
                                  duration=i % 4, tls_version=str(i % 4) if split != "test" else "unseen")
                             for i in range(80)]
        group = {"numeric": ["duration"], "categorical": ["tls_version"]}
        config = dict(labels=labels, seeds=[42], n_jobs=1, models={
            "random_forest": dict(n_estimators=4, max_depth=4),
            "xgboost": dict(n_estimators=4, max_depth=2),
            "lightgbm": dict(n_estimators=4, num_leaves=7, min_child_samples=2)})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch("src.models.baselines.make_model", wraps=make_model) as factory:
                runs = train_models(splits, {name: group for name in ("A", "B", "C")}, config, output)
            self.assertEqual(factory.call_count, 9)
            with (output / "summary.csv").open(encoding="utf-8-sig", newline="") as handle:
                summary = list(csv.DictReader(handle))
            self.assertEqual(len(summary), 9)
            self.assertEqual([(r["feature_group"], r["model"]) for r in summary],
                             [(group_name, model_name) for group_name in ("A", "B", "C")
                              for model_name in config["models"]])
            self.assertEqual(list(summary[0]), ["feature_group", "model", "accuracy_mean",
                "recall_macro_mean", "macro_f1_mean", "mcc_mean", "ap_attack_mean", "tpr_attack_mean", "fpr_attack_mean",
                "train_seconds_mean", "predict_seconds_mean"])
            for row in summary:
                for field in ("accuracy_mean", "recall_macro_mean", "macro_f1_mean", "ap_attack_mean", "tpr_attack_mean", "fpr_attack_mean"):
                    self.assertTrue(0 <= float(row[field]) <= 1)
                self.assertTrue(-1 <= float(row["mcc_mean"]) <= 1)
                self.assertGreaterEqual(float(row["train_seconds_mean"]), 0)
                self.assertGreaterEqual(float(row["predict_seconds_mean"]), 0)
            for run in runs:
                self.assertEqual(run["test"]["confusion_label_order"], labels)
                self.assertEqual(sum(map(sum, run["test"]["confusion_matrix"])), 80)
            self.assertEqual(sorted(p.name for p in output.iterdir()), ["summary.csv"])

    def test_imbalanced_metrics_use_attack_probabilities(self):
        labels = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
        truth = ["benign"] * 99 + ["attack_behavior"]
        result = metrics(truth, ["benign"] * 100, labels, [0.01] * 100)
        self.assertEqual(result["accuracy"], 0.99)
        self.assertEqual(result["mcc"], 0)
        self.assertAlmostEqual(result["ap_attack"], 0.01)
        perfect = metrics(truth, truth, labels, [0] * 99 + [1])
        self.assertEqual(perfect["mcc"], 1)
        self.assertEqual(perfect["ap_attack"], 1)
        self.assertIsNone(metrics(["benign"], ["benign"], labels, [0])["ap_attack"])


if __name__ == "__main__":
    unittest.main()
