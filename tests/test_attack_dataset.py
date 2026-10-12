"""Kiểm thử quota từng attack family, Nmap scope, password proof và bounds."""
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
from scripts.run_dataset_campaign import validate_campaign, make_run_config, collect, plan_supplement
from src.data_generation.generator import validate_config
from src.data_generation.attacks import AttackDatasetHarness, nmap_command, nmap_evidence
from src.features.aggregate_campaign import aggregate
from src.features.label_sessions import dataset_types, write_tables, write_schema, checksum, FEATURE_VERSION, LABEL_VERSION


class AttackDatasetTests(unittest.TestCase):
    def test_tls_readiness_retries_stale_certificate_before_labeling(self):
        config = json.loads((ROOT / "experiments/custom_dataset_attack_v3.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            harness = AttackDatasetHarness(config, Path(temporary), Path(temporary) / "manifest")
            replies = [subprocess.CompletedProcess([], 60, b"", b""),
                       subprocess.CompletedProcess([], 0, b"", b"")]
            with patch("src.data_generation.attacks.exec_lab", side_effect=replies) as execute, \
                 patch("src.data_generation.attacks.time.sleep"):
                harness.wait_tls_profile("/tmp/dataset_modern.crt")
            self.assertEqual(execute.call_count, 2)
            self.assertEqual(harness.rows, [])
            with patch("src.data_generation.attacks.exec_lab", return_value=replies[0]), \
                 patch("src.data_generation.attacks.time.sleep"):
                with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                    harness.wait_tls_profile("/tmp/dataset_modern.crt")

    def test_supplement_appends_late_blocks_once_with_benign_controls(self):
        config = self.config()
        original_days = json.loads(json.dumps(config["days"]))
        state = dict(config=config, mode="flexible", simple_output=True)
        plan_supplement(state, 1)
        self.assertEqual(config["days"][:5], original_days)
        self.assertEqual(config["days"][-1]["day"], 6)
        self.assertTrue(config["days"][-1]["retain_all_scenarios"])
        validate_campaign(config)
        day = config["days"][-1]
        run = make_run_config(config, 6, 0, 0, day["targets"], day["attack_targets"])
        self.assertEqual(set(run["scenarios"]), set(day["supplement_scenarios"]))
        self.assertIn("ssh_benign_password_retry", run["scenarios"])
        self.assertIn("tls_benign_periodic", run["scenarios"])
        plan_supplement(state, 1)
        self.assertEqual(len(config["days"]), 6)

    def test_benign_password_retry_has_two_rejections_then_success(self):
        config = json.loads((ROOT / "experiments/custom_dataset_attack_v3.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            harness = AttackDatasetHarness(config, Path(temporary), Path(temporary) / "manifest")
            calls = []
            def fake_exec(service, *args, **kwargs):
                if "ssh" in args:
                    calls.append(args)
                    if len(calls) < 3:
                        return subprocess.CompletedProcess([], 255, b"", b"Permission denied (password)")
                    return subprocess.CompletedProcess([], 0, b"", b"")
                return subprocess.CompletedProcess([], 0, b"ephemeral_test_value", b"")
            with patch("src.data_generation.attacks.exec_lab", side_effect=fake_exec), \
                 patch("src.data_generation.attacks.time.sleep"), patch.object(harness, "stop_password_fixture"):
                harness.password_attempts("ssh_benign_password_retry")
            self.assertEqual(harness.rows[0]["ground_truth_label"], "benign")
            self.assertEqual(harness.rows[0]["completed"], "true")
            evidence = harness.outcomes[0]["evidence"]
            self.assertEqual(evidence["failed_password_auth"], 2)
            self.assertEqual(evidence["successful_password_auth"], 1)
            self.assertNotIn("ephemeral_test_value", json.dumps(harness.outcomes))

    def config(self):
        return json.loads((ROOT / "experiments/campaign_attack_v3.json").read_text())

    def test_quotas_and_bounds(self):
        config = self.config()
        validate_campaign(config)
        totals = {label: sum(day["targets"][label] for day in config["days"]) for label in config["days"][0]["targets"]}
        self.assertEqual(totals, dict(benign=27000, misconfiguration=900, policy_violation=900, attack_behavior=1200))
        remaining = dict(benign=0, misconfiguration=0, policy_violation=0, attack_behavior=1)
        run = make_run_config(config, 2, 0, 0, remaining, {"ssh_password_guessing": 1})
        self.assertIn("ssh_password_guessing", run["scenarios"])
        self.assertNotIn("tls_beacon_jitter", run["scenarios"])
        run["tls_burst_concurrency"] = 10
        with self.assertRaises(ValueError):
            validate_config(run)
        config["days"][1]["attack_targets"]["ssh_password_guessing"] += 1
        with self.assertRaises(ValueError):
            validate_campaign(config)

    def test_background_dominant_scenario_schedule(self):
        config = self.config()
        for index in range(10):
            run = make_run_config(config, 2, 0, index, config["days"][1]["targets"], config["days"][1]["attack_targets"])
            from src.data_generation.generator import SCENARIOS
            abnormal = [name for name in run["scenarios"] if SCENARIOS[name][1] != "benign"]
            self.assertLessEqual(len(abnormal), 2)
            self.assertGreaterEqual(run["gap_seconds"], 20)
            self.assertLessEqual(run["gap_seconds"], 60)

    def test_nmap_no_arbitrary_target_payload_or_raw_scan(self):
        for name in ("nmap_tcp_connect_scan", "nmap_ssh_horizontal_scan"):
            command = nmap_command(name)
            self.assertIn("-sT", command)
            self.assertNotIn("-sV", command)
            self.assertNotIn("--script", command)
            self.assertEqual(command[command.index("--max-rate") + 1], "10")
        with self.assertRaises(ValueError):
            nmap_command("external_target")
        xml = b'<nmaprun><host><address addrtype="ipv4" addr="172.30.20.10"/><ports><extraports count="6" state="closed"/><port><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        report = nmap_evidence(xml, [("proxy", p) for p in (4443, *range(4450, 4456))])
        self.assertEqual(report["completed_hosts"], 1)
        self.assertFalse(report["raw_scan_output_retained"])
        with self.assertRaises(RuntimeError):
            nmap_evidence(xml.replace(b'count="6"', b'count="2"'), [("proxy", p) for p in (4443, *range(4450, 4456))])

    def test_collection_does_not_skip_a_missing_family(self):
        config = self.config()
        config["days"] = [config["days"][1]]
        config["days"][0].update(targets=dict(benign=0, misconfiguration=0, policy_violation=0, attack_behavior=4),
            attack_targets={"ssh_password_guessing": 2, "tls_beacon_jitter": 2})
        previous = [{"ground_truth_label": "attack_behavior", "expected_behavior": "ssh_password_guessing"}] * 4
        state = dict(campaign_id="test", mode="flexible", start_date="2099-01-01", config=config, runs=[])
        with tempfile.TemporaryDirectory() as temporary:
            with patch("scripts.run_dataset_campaign.read_runs", return_value=(previous, [])), patch("scripts.run_dataset_campaign.generate") as generate:
                collect(state, Path(temporary) / "state.json", max_runs=1)
        scenarios = generate.call_args.args[0]["scenarios"]
        self.assertEqual(scenarios, ["tls_beacon_jitter"])

    def test_spraying_has_auth_proof_without_retained_credentials(self):
        config = json.loads((ROOT / "experiments/custom_dataset_attack_v3.json").read_text())
        config.update(password_attempts=6)
        with tempfile.TemporaryDirectory() as temporary:
            harness = AttackDatasetHarness(config, Path(temporary), Path(temporary) / "manifest")
            result = subprocess.CompletedProcess([], 255, b"", b"Permission denied (password)")
            with patch("src.data_generation.attacks.exec_lab", return_value=result), patch("src.data_generation.attacks.time.sleep"), patch.object(harness, "stop_password_fixture"):
                harness.password_attempts("ssh_password_spraying")
            outcome = harness.outcomes[0]
            self.assertEqual(outcome["evidence"]["distinct_lab_accounts"], 3)
            self.assertEqual(outcome["evidence"]["failed_password_auth"], 6)
            self.assertNotIn("topic4spray1", json.dumps(outcome))
            self.assertNotIn("password_value", json.dumps(outcome))

    def test_wrong_password_failure_is_not_attack_success(self):
        config = json.loads((ROOT / "experiments/custom_dataset_attack_v3.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            harness = AttackDatasetHarness(config, Path(temporary), Path(temporary) / "manifest")
            result = subprocess.CompletedProcess([], 137, b"", b"timeout")
            with patch("src.data_generation.attacks.exec_lab", return_value=result), patch.object(harness, "stop_password_fixture"):
                with self.assertRaises(RuntimeError):
                    harness.password_attempts("ssh_password_guessing")
            self.assertEqual(harness.rows[0]["completed"], "false")

    def test_genuine_benign_surplus_is_kept_without_duplicate_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "source"
            artifact.mkdir()
            rows = []
            for index in range(3):
                row = dict.fromkeys(dataset_types(), "")
                row.update(uid=f"u{index}", run_id="fixture", scenario_id="normal", timestamp_unix=str(100 + index),
                    timestamp_utc=datetime.fromtimestamp(100 + index, timezone.utc).isoformat(), transport_protocol="tcp", application_protocol="tls",
                    src_ip="172.30.10.10", dst_ip="172.30.20.10", src_port="50000", dst_port="443",
                    ground_truth_label="benign", src_role="client", dst_role="proxy", feature_version=FEATURE_VERSION,
                    label_version=LABEL_VERSION, label_status="matched", expected_behavior="authorized_background", duration_seconds="1")
                rows.append(row)
            write_tables(artifact, rows, []); write_schema(artifact)
            (artifact / "run_status.json").write_text(json.dumps({"completed": True, "cleanup_passed": True}))
            (artifact / "checksums.json").write_text(json.dumps({"labeled_sessions.csv": checksum(artifact / "labeled_sessions.csv")}))
            record = dict(status="complete", run_id="fixture", artifact=str(artifact), day=1, slot="batch_1", round=0)
            config = {"seed": 1, "retain_benign_surplus": True, "days": [{"day": 1,
                "targets": dict(benign=1, misconfiguration=0, policy_violation=0, attack_behavior=0)}]}
            report = aggregate(dict(campaign_id="fixture", mode="flexible", config=config, runs=[record]), Path(temporary) / "out")
            self.assertEqual(report["selected_rows"], 3)
            self.assertEqual(report["target_rows"], 1)
            self.assertTrue(report["quota_complete"])
            self.assertEqual(report["class_percentages"], {"benign": 100.0})

    def test_family_shortfall_not_hidden_by_many_other_attacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "source"
            artifact.mkdir()
            rows = []
            for index in range(4):
                row = dict.fromkeys(dataset_types(), "")
                row.update(uid=f"u{index}", run_id="fixture", scenario_id="guessing", timestamp_unix=str(100 + index),
                    timestamp_utc=datetime.fromtimestamp(100 + index, timezone.utc).isoformat(), transport_protocol="tcp", application_protocol="ssh",
                    src_ip="172.30.10.10", dst_ip="172.30.20.20", src_port="50000", dst_port="2223",
                    ground_truth_label="attack_behavior", src_role="client", dst_role="bastion", feature_version=FEATURE_VERSION,
                    label_version=LABEL_VERSION, label_status="matched", expected_behavior="ssh_password_guessing", duration_seconds="1")
                rows.append(row)
            write_tables(artifact, rows, []); write_schema(artifact)
            (artifact / "run_status.json").write_text(json.dumps({"completed": True, "cleanup_passed": True}))
            (artifact / "checksums.json").write_text(json.dumps({"labeled_sessions.csv": checksum(artifact / "labeled_sessions.csv")}))
            record = dict(status="complete", run_id="fixture", artifact=str(artifact), day=2, slot="batch_1", round=0)
            config = {"seed": 1, "dataset_scope": "all_labeled_sessions", "days": [{"day": 2,
                "targets": dict(benign=0, misconfiguration=0, policy_violation=0, attack_behavior=4),
                "attack_targets": {"ssh_password_guessing": 2, "tls_beacon_jitter": 2}}]}
            report = aggregate(dict(campaign_id="fixture", mode="flexible", config=config, runs=[record]), Path(temporary) / "out")
            self.assertEqual(report["selected_rows"], 2)
            self.assertFalse(report["quota_complete"])
            # Supplement keeps the collected surplus, but still reports missing families.
            config["days"][0]["retain_all_scenarios"] = True
            supplemented = aggregate(dict(campaign_id="fixture", mode="flexible", config=config, runs=[record]), Path(temporary) / "out")
            self.assertEqual(supplemented["selected_rows"], 4)
            self.assertFalse(supplemented["quota_complete"])
            self.assertEqual(report["shortfalls"], {"day2_attack_tls_beacon_jitter": 2})


if __name__ == "__main__":
    unittest.main()
