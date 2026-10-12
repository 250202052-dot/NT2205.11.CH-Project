"""Scenario v2: reuse Harness, keep normal TLS/HTTP/SSH running concurrently.

Fixture TLS lives on temporary ports in the same proxy; no new permanent
container. Ground truth comes from the controlled action, not detector alerts.
"""
import hashlib
import json
import time

from src.data_generation.generator import Harness, ROOT, SCENARIOS, write_manifest
from src.data_generation.runtime import exec_lab

TLS_PORTS = (4443, 4444)
SCAN_PORTS = tuple(range(4450, 4456))


class DatasetHarnessV2(Harness):
    def __init__(self, *args):
        super().__init__(*args)
        self.v2_firewalls = []
        self.v2_tls_owned = False
        self.v2_script = (ROOT / "docker/proxy/dataset-tls-v2.sh").read_bytes()

    def tls_fixture(self, profile):
        exec_lab("proxy", "sh", "-s", "--", profile, data=self.v2_script, timeout=30)
        # nginx reload is asynchronous; bounded readiness check before window.
        if profile != "stop":
            exec_lab("proxy", "sh", "-c",
                "i=0; until curl -fsSk --max-time 2 --tls-max 1.2 --ciphers 'ALL:@SECLEVEL=0' https://127.0.0.1:4443/api/status >/dev/null; do i=$((i+1)); [ $i -lt 10 ] || exit 1; sleep 1; done", timeout=35)

    def prepare(self):
        if exec_lab("proxy", "test", "-e", "/etc/nginx/conf.d/topic4-dataset-v2.conf", check=False).returncode == 0:
            raise ValueError("An interrupted v2 TLS fixture exists; recover it first")
        enabled = exec_lab("zeek", "printenv", "ZEEK_EXTENDED_METADATA").stdout.decode().strip().lower()
        if self.config.get("require_extended_metadata", True) and enabled != "true":
            raise ValueError("v2 needs ZEEK_EXTENDED_METADATA=true; recreate Zeek before collection")
        if self.config.get("require_extended_metadata", True):
            # ENV=true chưa đủ: image cũ có thể bỏ qua biến này trong entrypoint.
            running = exec_lab("zeek", "pgrep", "-a", "zeek").stdout.split()
            if b"/config/extended_profile.zeek" not in running:
                raise ValueError("Zeek image is stale: run docker compose build zeek, then recreate Zeek with ZEEK_EXTENDED_METADATA=true")
        super().prepare()
        for port in TLS_PORTS + SCAN_PORTS:
            rule = ["FORWARD", "-s", "172.30.10.10", "-d", "172.30.20.10", "-p", "tcp", "--dport", str(port),
                    "-m", "comment", "--comment", "topic4-dataset-v2", "-j", "ACCEPT"]
            if exec_lab("router", "iptables", "-C", *rule, check=False).returncode == 0:
                raise ValueError("An interrupted v2 firewall rule exists; recover it first")
            exec_lab("router", "iptables", "-I", "FORWARD", "1", *rule[1:])
            self.v2_firewalls.append(rule)
        # Set ownership before init, so a partial setup is also cleaned up.
        self.v2_tls_owned = True
        self.tls_fixture("init")
        self.tls_request(4443, verify=True)

    def tls_request(self, port=4443, verify=False):
        trust = ["--cacert", "/tmp/dataset_modern.crt"] if verify else ["-k"]
        return exec_lab("client", "curl", "-fsS", *trust, "--max-time", "8", "--tls-max", "1.2",
            "--ciphers", "ALL:@SECLEVEL=0", "--resolve", f"proxy.topic4.lab:{port}:172.30.20.10",
            "-o", "/dev/null", f"https://proxy.topic4.lab:{port}/api/status", timeout=15)

    def row(self, name, label, protocol, dst_role, port, **extra):
        return dict(scenario_id=name, start_time=time.time(), end_time="", src_role="client",
            dst_role=dst_role, protocol=protocol, expected_rule=SCENARIOS[name][2], ground_truth_label=label,
            expected_behavior=name, dst_port=port, scenario_type="benign_maintenance" if label == "benign" else "abnormal",
            completed="false", fixture_version="lab-fixtures-v2", ground_truth_source="controlled_lab_execution",
            attack_family=name if label == "attack_behavior" else "", change_authorized=str(label == "benign").lower(), **extra)

    def persist(self, row):
        row["end_time"] = time.time()
        self.rows.append(row)
        self.write_scenario_manifest(row)
        write_manifest(self.manifests / "scenario_manifest.csv", self.rows)

    def run_scenario(self, name):
        if name.startswith("ssh_") and name != "ssh_lateral_sequence":
            return super().run_scenario(name)
        if name == "ssh_lateral_sequence":
            return self.lateral_sequence(name)
        if name.startswith("l3_"):
            return self.scan(name)
        profile, label, _ = SCENARIOS[name]
        self.tls_fixture(profile)
        port = 4444 if name == "tls_interception_fixture" else 4443
        row = self.row(name, label, "tls", "proxy", port)
        attempts = 0
        evidence = {"fixture_profile": profile, "route": f"client->router->proxy:{port}",
                    "authorized_test_fixture": True}
        try:
            cert_path = "/tmp/topic4-dataset-tls-v2/interception.crt" if port == 4444 else (
                "/tmp/topic4-dataset-tls-v2/weak.crt" if profile == "weak" else f"/etc/nginx/tls/{profile}/server.crt")
            cert = exec_lab("proxy", "openssl", "x509", "-in", cert_path, "-outform", "DER").stdout
            evidence["certificate_der_sha256"] = hashlib.sha256(cert).hexdigest()
            deadline = time.monotonic() + self.config["window_seconds"]
            if name == "tls_session_resumption":
                # OpenSSL reconnect reuses the session. Keep ONLY aggregate proof,
                # never its stdout: it may contain master-key/session details.
                # Filter stdout inside the container: session secrets never
                # cross Docker stdout or enter Python/artifact output.
                command = "set -o pipefail; timeout -s KILL 12 openssl s_client -connect 172.30.20.10:4443 -servername proxy.topic4.lab -tls1_2 -CAfile /tmp/dataset_modern.crt -verify_return_error -reconnect </dev/null 2>/dev/null | awk '/^Reused, TLS/{n++} END {print n+0}'"
                result = exec_lab("client", "sh", "-c", command, check=False, timeout=20)
                evidence["reused_sessions"] = int(result.stdout.strip() or b"0")
                if result.returncode or not evidence["reused_sessions"]:
                    raise RuntimeError("TLS resumption fixture produced no verified reuse")
                attempts = 6
                time.sleep(max(3, self.config["background_http_interval"] * 2))
            else:
                while True:
                    if name == "tls_benign_client_change" and attempts % 2:
                        # Discard response inside client, before Docker stdout:
                        # the dataset generator must not ingest HTTP content.
                        result = exec_lab("client", "sh", "-c",
                            "timeout -s KILL 10 openssl s_client -quiet -connect 172.30.20.10:4443 -servername proxy.topic4.lab -tls1_2 -CAfile /tmp/dataset_modern.crt -verify_return_error >/dev/null 2>/dev/null",
                            data=b"GET /api/status HTTP/1.0\r\nHost: proxy.topic4.lab\r\n\r\n", timeout=15)
                        evidence["client_families"] = ["curl", "openssl_s_client"]
                    else:
                        # Renewal accepts the scheduled identity; anomalies are
                        # observed with -k, which is NOT proof of trust validity.
                        verify = profile == "modern"
                        if name == "tls_benign_renewal":
                            cert = exec_lab("proxy", "cat", cert_path).stdout
                            exec_lab("client", "sh", "-c", "cat > /tmp/dataset_renewal.crt", data=cert)
                            exec_lab("client", "curl", "-fsS", "--cacert", "/tmp/dataset_renewal.crt", "--max-time", "8",
                                "--tls-max", "1.2", "--resolve", "proxy.topic4.lab:4443:172.30.20.10", "-o", "/dev/null",
                                "https://proxy.topic4.lab:4443/api/status", timeout=15)
                        else:
                            self.tls_request(port, verify)
                    attempts += 1
                    if time.monotonic() >= deadline:
                        break
                    interval = self.config.get("beacon_interval", 2) if name in {"tls_encrypted_beacon", "tls_benign_healthcheck"} else self.config["scenario_interval"]
                    jitter = self.config.get("beacon_jitter", 0.15) if name == "tls_encrypted_beacon" else 0
                    time.sleep(interval * self.workload_rng.uniform(1 - jitter, 1 + jitter))
                if name in {"tls_encrypted_beacon", "tls_benign_healthcheck"}:
                    evidence.update(interval_seconds=interval, timing_only_simulation=True, no_malware=True)
            row["completed"] = "true"
        finally:
            self.persist(row)
            self.outcomes.append(dict(scenario_id=name, attempts=attempts, completed=row["completed"], evidence=evidence))
            self.tls_fixture("modern")

    def lateral_sequence(self, name):
        # Observe inner bastion->backend/db edges. Valid lab key, no exploitation.
        for target in ("backend", "db"):
            row = self.row(name, "attack_behavior", "ssh", target, 22)
            row.update(scenario_id=f"{name}_{target}", src_role="bastion")
            try:
                for _ in range(3):
                    exec_lab("client", "timeout", "-s", "KILL", "15", "ssh", target, "true", timeout=30)
                    time.sleep(self.config["scenario_interval"])
                time.sleep(max(3, self.config["background_http_interval"] * 2))
                row["completed"] = "true"
            finally:
                self.persist(row)
                self.outcomes.append(dict(scenario_id=row["scenario_id"], completed=row["completed"],
                    attempts=3, evidence={"authorized_lab_key": True, "scripted_path": f"client->bastion->{target}",
                    "compromise_simulated": False}))

    def scan(self, name):
        # These six CLOSED ports are inside the lab. No arbitrary target input.
        # Benign inventory is slower; both have explicit schedule ground truth.
        started = time.time()
        rows = []
        for port in SCAN_PORTS:
            label = SCENARIOS[name][1]
            row = self.row(name, label, "tcp", "proxy", port)
            row["scenario_id"] = f"{name}_{port}"
            row["start_time"] = started
            result = None
            try:
                result = exec_lab("client", "curl", "-s", "--connect-timeout", "1", "--max-time", "2",
                    "-o", "/dev/null", f"http://172.30.20.10:{port}/", timeout=8, check=False)
                if result.returncode != 7:
                    raise RuntimeError("Scan fixture expected a closed-port connection refusal")
                # Leave room for Zeek's session duration at the window boundary.
                time.sleep(0.3)
                row["completed"] = "true"
            finally:
                rows.append(row)
                self.outcomes.append(dict(scenario_id=row["scenario_id"], completed=row["completed"], attempts=1,
                    evidence={"closed_port": port, "connection_refused": result is not None and result.returncode == 7}))
                if row["completed"] != "true":
                    for item in rows:
                        self.persist(item)
            time.sleep(0.2 if label == "attack_behavior" else self.config.get("inventory_interval", 2))
        time.sleep(max(3, self.config["background_http_interval"] * 2))
        for row in rows:
            self.persist(row)

    def cleanup(self):
        failures = []
        if self.v2_tls_owned:
            try:
                self.tls_fixture("stop")
            except Exception:
                failures.append("v2_tls")
        for rule in reversed(self.v2_firewalls):
            try:
                exec_lab("router", "iptables", "-D", *rule)
            except Exception:
                failures.append("v2_firewall")
        super().cleanup()
        if failures:
            raise RuntimeError(f"v2 cleanup failed: {failures}")
