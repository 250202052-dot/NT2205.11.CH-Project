"""Run continuous benign background and bounded scenarios in the existing Docker lab."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import csv
import json
import os
from pathlib import Path
import random
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.data_generation.runtime import docker, exec_lab, trust_hosts, LabCommandTimeout
from src.features.build_sessions import read_log_index, iter_log_records
from src.features.label_sessions import label_dataset, MANIFEST_REQUIRED, checksum

SCENARIOS = {
    "tls_weak_cipher": ("weak", "policy_violation", "TLS_CIPHER_NOT_ALLOWED"),
    "tls_weak_key": ("weak-cert", "misconfiguration", "TLS_RSA_KEY_TOO_SMALL"),
    "tls_expired_cert": ("expired-cert", "misconfiguration", "TLS_CERT_EXPIRED"),
    "tls_hostname_mismatch": ("wrong-host", "misconfiguration", "TLS_CERT_HOSTNAME_MISMATCH"),
    "ssh_weak_kex": ("weak-kex", "policy_violation", "SSH_KEX_WEAK"),
    "ssh_weak_cipher": ("weak-cipher", "policy_violation", "SSH_CIPHER_WEAK"),
    "ssh_weak_mac": ("weak-mac", "policy_violation", "SSH_MAC_WEAK"),
    "ssh_weak_host_key": ("weak-host-key", "policy_violation", "SSH_HOST_KEY_SIGNATURE_WEAK"),
    "ssh_bruteforce_like": ("modern", "attack_behavior", "SSH_CONNECTION_BURST"),
    "ssh_new_path": (None, "policy_violation", "SSH_NEW_PATH"),
    "tls_benign_renewal": ("replaced-cert", "benign", ""),
    "tls_unexpected_certificate": ("replaced-cert", "policy_violation", ""),
    "tls_interception_fixture": ("interception", "attack_behavior", ""),
    "tls_encrypted_beacon": ("modern", "attack_behavior", ""),
    "tls_benign_healthcheck": ("modern", "benign", ""),
    "tls_session_resumption": ("modern", "benign", ""),
    "tls_benign_client_change": ("modern", "benign", ""),
    "ssh_lateral_sequence": (None, "attack_behavior", ""),
    "l3_scan_burst": (None, "attack_behavior", ""),
    "l3_benign_inventory": (None, "benign", ""),
    "ssh_password_guessing": (None, "attack_behavior", ""),
    "ssh_password_spraying": (None, "attack_behavior", ""),
    "tls_beacon_jitter": ("modern", "attack_behavior", ""),
    "tls_beacon_burst": ("modern", "attack_behavior", ""),
    "tls_connection_burst": ("modern", "attack_behavior", ""),
    "nmap_tcp_connect_scan": (None, "attack_behavior", ""),
    "nmap_ssh_horizontal_scan": (None, "attack_behavior", ""),
    "tls_beacon_slow": ("modern", "attack_behavior", ""),
    "tls_beacon_variable": ("modern", "attack_behavior", ""),
    "tls_connection_burst_variable": ("modern", "attack_behavior", ""),
    "tls_benign_periodic": ("modern", "benign", ""),
    "tls_benign_burst": ("modern", "benign", ""),
    "ssh_password_guessing_slow": (None, "attack_behavior", ""),
    "ssh_password_spraying_slow": (None, "attack_behavior", ""),
    "ssh_benign_password_retry": (None, "benign", ""),
    "ssh_lateral_variable": (None, "attack_behavior", ""),
    "ssh_benign_lateral_variable": (None, "benign", ""),
    "tls_interception_sameport": ("interception-sameport", "attack_behavior", ""),
    "tls_policy_regression": ("weak", "policy_violation", "TLS_CIPHER_NOT_ALLOWED"),
}
# version, OpenSSL cipher name, certificate profile, label
TLS_PROFILES = {
    "tls12_rsa_aes256_gcm": ("1.2", "ECDHE-RSA-AES256-GCM-SHA384", "modern", "benign"),
    "tls12_rsa_chacha20": ("1.2", "ECDHE-RSA-CHACHA20-POLY1305", "modern", "benign"),
    "tls12_ecdsa_aes128_gcm": ("1.2", "ECDHE-ECDSA-AES128-GCM-SHA256", "ecdsa", "benign"),
    "tls13_aes128_gcm": ("1.3", "TLS_AES_128_GCM_SHA256", "modern", "benign"),
    "tls13_aes256_gcm": ("1.3", "TLS_AES_256_GCM_SHA384", "modern", "benign"),
    "tls13_chacha20": ("1.3", "TLS_CHACHA20_POLY1305_SHA256", "modern", "benign"),
    "tls12_rsa_aes256_cbc": ("1.2", "AES256-SHA", "modern", "policy_violation"),
    "tls12_ecdhe_aes128_cbc": ("1.2", "ECDHE-RSA-AES128-SHA256", "modern", "policy_violation"),
    "tls12_static_rsa_aes128_gcm": ("1.2", "AES128-GCM-SHA256", "modern", "policy_violation"),
}

# kex, cipher, MAC, host-key signature, label
SSH_PROFILES = {
    "ssh_curve25519_chacha20": ("curve25519-sha256", "chacha20-poly1305@openssh.com", "hmac-sha2-256", "ssh-ed25519", "benign"),
    "ssh_curve25519_aes256_gcm": ("curve25519-sha256", "aes256-gcm@openssh.com", "hmac-sha2-256", "ssh-ed25519", "benign"),
    "ssh_group14_sha256_aes256_ctr": ("diffie-hellman-group14-sha256", "aes256-ctr", "hmac-sha2-512-etm@openssh.com", "rsa-sha2-512", "benign"),
    "ssh_ecdh_ecdsa_aes128_ctr": ("ecdh-sha2-nistp256", "aes128-ctr", "hmac-sha2-256-etm@openssh.com", "ecdsa-sha2-nistp256", "benign"),
    "ssh_legacy_group1_sha1": ("diffie-hellman-group1-sha1", "aes128-ctr", "hmac-sha2-256", "ssh-ed25519", "policy_violation"),
    "ssh_legacy_aes256_cbc": ("curve25519-sha256", "aes256-cbc", "hmac-sha2-256", "ssh-ed25519", "policy_violation"),
    "ssh_legacy_hmac_md5": ("curve25519-sha256", "aes128-ctr", "hmac-md5", "ssh-ed25519", "policy_violation"),
}


def crypto_scenarios():
    rules = {"ssh_legacy_group1_sha1": "SSH_KEX_WEAK", "ssh_legacy_aes256_cbc": "SSH_CIPHER_WEAK",
             "ssh_legacy_hmac_md5": "SSH_MAC_WEAK"}
    result = {name: (name, spec[-1], "TLS_CIPHER_NOT_ALLOWED" if spec[-1] != "benign" else "")
              for name, spec in TLS_PROFILES.items()}
    result.update({name: (name, spec[-1], rules.get(name, "")) for name, spec in SSH_PROFILES.items()})
    return result
SCENARIOS.update(crypto_scenarios())
MANIFEST_COLUMNS = MANIFEST_REQUIRED + ["expected_behavior", "dst_port", "scenario_type", "completed",
    "src_port", "dst_ip", "fixture_version", "attack_family", "ground_truth_source", "change_authorized",
    "attack_mapping", "execution_tool", "evidence_scope"]
FIREWALL = ["FORWARD", "-s", "172.30.10.10", "-d", "172.30.20.20", "-p", "tcp",
            "--dport", "2223", "-m", "comment", "--comment", "topic4-custom-dataset", "-j", "ACCEPT"]


def write_manifest(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def snapshot_logs(destination, start, end):
    source = ROOT / "data/lab_metadata/zeek"
    destination.mkdir(parents=True, exist_ok=True)
    connections = read_log_index(source, "conn", "uid")
    connections = {uid: r for uid, r in connections.items() if start <= r["ts"] < end}
    selected = {"conn": list(connections.values())}
    for stream in ("ssl", "ssh", "packet_metadata", "tls_extensions"):
        selected[stream] = [r for uid, r in read_log_index(source, stream, "uid").items() if uid in connections]
    fingerprints = {fp for r in selected["ssl"] for name in ("cert_chain_fps", "client_cert_chain_fps") for fp in r.get(name, [])}
    selected["x509"] = [r for fp, r in read_log_index(source, "x509", "fingerprint").items() if fp in fingerprints]
    for stream in ("notice", "weird"):
        records = {}
        for r in iter_log_records(source, stream):
            if r.get("uid") in connections or start <= r.get("ts", 0) < end:
                records[json.dumps(r, sort_keys=True)] = r
        selected[stream] = list(records.values())
    for stream, rows in selected.items():
        with (destination / f"{stream}.log").open("w", encoding="utf-8") as handle:
            for row in sorted(rows, key=lambda r: r.get("ts", 0)):
                handle.write(json.dumps(row) + "\n")


class Harness:
    def __init__(self, config, artifact, manifests):
        self.config, self.artifact, self.manifests = config, artifact, manifests
        self.stop = threading.Event()
        self.threads = []
        self.background_counts = Counter()
        self.background_failures = Counter()
        self.background_events = []
        self.tls_guard = threading.Lock()
        self.tls_background_enabled = False
        self.tls_background_start = None
        self.tls_benign_intervals = []
        self.lock = threading.Lock()
        self.original_profile = None
        self.client_existed = None
        self.client_ready = False
        self.previous_known_hosts = None
        self.firewall_added = False
        self.rows = []
        self.outcomes = []
        self.ssh_timeouts = Counter()
        self.ssh_script = (ROOT / "docker/bastion/dataset-sshd.sh").read_bytes()
        self.workload_rng = random.Random(config["seed"] + 100)

    def write_scenario_manifest(self, row):
        # Output gọn: một manifest chung, không tạo folder cho từng kết nối.
        if not self.config.get("single_manifest", False):
            write_manifest(self.manifests / row["scenario_id"] / "scenario_manifest.csv", [row])

    def activate_tls(self, profile):
        env = dict(os.environ, TLS_PROFILE=profile)
        docker("compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "40", "proxy", env=env)

    def fixture(self, profile):
        exec_lab("bastion", "sh", "-s", "--", profile, data=self.ssh_script, timeout=15)
        if profile != "stop":
            known = exec_lab("bastion", "cat", "/tmp/topic4-dataset-ssh/known_hosts").stdout
            exec_lab("client", "sh", "-c", "cat > /tmp/dataset_known_hosts", data=known)

    def prepare(self):
        states = docker("compose", "ps", "--format", "json").stdout.decode()
        parsed = json.loads(states) if states.lstrip().startswith("[") else [json.loads(line) for line in states.splitlines() if line]
        ready = {r["Service"] for r in parsed if r.get("Health") == "healthy"}
        required = {"router", "web-frontend", "backend", "db", "proxy", "bastion", "zeek"}
        if not required <= ready:
            raise ValueError("Start the lab first; all 7 main services must be healthy")
        sensor_time = float(exec_lab("zeek", "date", "+%s").stdout.decode())
        if abs(time.time() - sensor_time) > 3:
            raise ValueError("Host and sensor clocks differ by more than 3 seconds")
        self.original_profile = exec_lab("proxy", "printenv", "TLS_PROFILE").stdout.decode().strip()
        self.client_existed = bool(docker("compose", "ps", "-a", "-q", "client").stdout.strip())
        docker("compose", "--profile", "test", "up", "-d", "client")
        self.client_ready = True
        if self.client_existed:
            saved = exec_lab("client", "cat", "/root/.ssh/known_hosts", check=False)
            self.previous_known_hosts = saved.stdout if saved.returncode == 0 else b""
        trust_hosts()
        # Do not touch a listener/firewall belonging to an interrupted prior run.
        if exec_lab("bastion", "test", "-e", "/tmp/topic4-dataset-ssh/pid", check=False).returncode == 0:
            raise ValueError("A dataset SSH fixture already exists; recover it before running")
        if exec_lab("router", "iptables", "-C", *FIREWALL, check=False).returncode == 0:
            raise ValueError("A dataset firewall rule already exists; recover it before running")
        exec_lab("router", "iptables", "-I", FIREWALL[0], "1", *FIREWALL[1:])
        self.firewall_added = True
        self.activate_tls("modern")
        cert = exec_lab("proxy", "cat", "/etc/nginx/tls/modern/server.crt").stdout
        exec_lab("client", "sh", "-c", "cat > /tmp/dataset_modern.crt", data=cert)
        exec_lab("client", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/tmp/dataset_wrong_key")
        # Fresh cache before collection; never restart Zeek between scenarios.
        docker("compose", "restart", "zeek")
        docker("compose", "up", "-d", "--no-deps", "--wait", "zeek")

    def background(self, kind, interval, operation, seed):
        rng = random.Random(seed)
        while not self.stop.is_set():
            started = time.time()
            success = False
            try:
                if operation() is False:
                    self.stop.wait(min(interval, 0.5))
                    continue
                success = True
                with self.lock:
                    self.background_counts[kind] += 1
            except Exception:
                with self.lock:
                    self.background_failures[kind] += 1
            with self.lock:
                self.background_events.append({"kind": kind, "start_time": started, "end_time": time.time(), "success": success})
            self.stop.wait(interval * rng.uniform(0.9, 1.1))

    def start_background(self):
        self.enable_tls_background()
        operations = [
            ("http_internal", self.config["background_http_interval"],
             self.benign_http_action),
            ("ssh_authorized", self.config["background_ssh_interval"],
             self.benign_ssh_action),
            ("tls_modern", self.config["background_http_interval"], self.benign_tls_action),
        ]
        for index, (name, interval, operation) in enumerate(operations):
            thread = threading.Thread(target=self.background, args=(name, interval, operation, self.config["seed"] + index))
            thread.start()
            self.threads.append(thread)

    def benign_http_action(self):
        path = self.workload_rng.choice(["status", "products", "products"] if self.config.get("diverse_workload") else ["status"])
        exec_lab("web-frontend", "curl", "-fsS", "--max-time", "3", "-o", "/dev/null",
                 f"http://172.30.30.20:8000/api/{path}", timeout=8)

    def benign_ssh_action(self):
        ranges = self.config.get("ssh_hold_ranges", [[0, 0]])
        low, high = self.workload_rng.choice(ranges)
        hold = round(self.workload_rng.uniform(low, high), 2)
        exec_lab("client", "timeout", "-s", "KILL", str(hold + 10), "ssh",
                 "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2",
                 "web-frontend", "sleep", str(hold), timeout=hold + 25)

    def benign_tls_action(self):
        with self.tls_guard:
            if not self.tls_background_enabled:
                return False
            version = self.workload_rng.choice(self.config.get("tls_versions", ["1.2"]))
            path = self.workload_rng.choice(["status", "products", "products"] if self.config.get("diverse_workload") else ["status"])
            rate = self.workload_rng.choice(self.config.get("tls_rate_limits", [0]))
            options = ["--limit-rate", str(rate)] if rate else []
            exec_lab("client", "curl", "-fsS", "--max-time", "30", "--tls-max", version,
                     *( ["--tlsv1.3"] if version == "1.3" else [] ), *options,
                     "--cacert", "/tmp/dataset_modern.crt", "--resolve", "proxy.topic4.lab:443:172.30.20.10",
                     "-o", "/dev/null", f"https://proxy.topic4.lab/api/{path}", timeout=35)

    def enable_tls_background(self):
        with self.tls_guard:
            self.tls_background_enabled = True
            self.tls_background_start = time.time()

    def pause_tls_background(self):
        with self.tls_guard:
            self.tls_background_enabled = False
            if self.tls_background_start is not None:
                self.tls_benign_intervals.append((self.tls_background_start, time.time()))
                self.tls_background_start = None

    def stop_background(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=max(35, max((r[1] for r in self.config.get("ssh_hold_ranges", [[0, 0]])), default=0) + 25))
            if thread.is_alive():
                raise RuntimeError("Background did not stop within timeout")
        self.pause_tls_background()

    def ssh_action(self, name):
        if name == "ssh_new_path":
            return exec_lab("client", "timeout", "-s", "KILL", "15", "ssh",
                            "-o", "ConnectTimeout=3", "backend", "true", timeout=30)
        profile = SCENARIOS[name][0]
        options = {"weak-kex": ["-o", "KexAlgorithms=diffie-hellman-group14-sha1"],
                   "weak-cipher": ["-c", "aes128-cbc"], "weak-mac": ["-m", "hmac-sha1"],
                   "weak-host-key": ["-o", "HostKeyAlgorithms=ssh-rsa"]}.get(profile, [])
        cipher = "aes128-cbc" if profile == "weak-cipher" else "aes128-ctr"
        if name in SSH_PROFILES:
            kex, cipher, mac, host_alg, _ = SSH_PROFILES[name]
            options = ["-o", f"KexAlgorithms={kex}", "-m", mac, "-o", f"HostKeyAlgorithms={host_alg}"]
        wrong = name == "ssh_bruteforce_like"
        # Giới hạn process SSH ngay trong client, không chỉ giới hạn Docker CLI.
        command = ["timeout", "-s", "KILL", "15", "ssh", "-F", "/dev/null", "-p", "2223",
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=yes",
             "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2",
             "-o", "UserKnownHostsFile=/tmp/dataset_known_hosts", "-o", "IdentitiesOnly=yes",
             "-o", "IdentityAgent=none", "-i", "/tmp/dataset_wrong_key" if wrong else "/root/.ssh/id_ed25519",
             "-c", cipher,
             *options, "labadmin@172.30.20.20", "true"]
        # Retry chỉ dành cho timeout, tối đa ba lần; không retry lỗi host key/auth
        # không đúng kỳ vọng. Thời gian mỗi lần thử vẫn được ghi thực trong window.
        for attempt in range(3):
            try:
                result = exec_lab("client", *command, check=False, timeout=30)
                timed_out = result.returncode in {124, 137, -9}
            except LabCommandTimeout:
                timed_out = True
            if not timed_out:
                break
            self.ssh_timeouts[name] += 1
            if attempt == 2:
                raise RuntimeError(f"SSH fixture {name} timed out after 3 bounded attempts; round excluded, use --resume")
            print(f"Retry {name}: SSH timeout ({attempt + 1}/3)", flush=True)
            time.sleep(1)
        if wrong:
            if result.returncode != 255 or b"Permission denied" not in result.stderr:
                raise RuntimeError("Brute-force-like fixture did not produce expected public-key rejection")
        elif result.returncode:
            raise RuntimeError(f"SSH fixture {name} failed (exit {result.returncode})")
        return result

    def run_scenario(self, name):
        profile, label, rule = SCENARIOS[name]
        tls = name.startswith("tls_")
        if tls:
            self.pause_tls_background()
            if self.config.get("refresh_tls_fixtures"):
                exec_lab("proxy", "sh", "-s", "--", profile, "refresh-fixture",
                         data=(ROOT / "docker/proxy/create-certificate.sh").read_bytes(), timeout=15)
            self.activate_tls(profile)
            if name == "tls_benign_renewal":
                cert = exec_lab("proxy", "cat", "/etc/nginx/tls/replaced-cert/server.crt").stdout
                exec_lab("client", "sh", "-c", "cat > /tmp/dataset_renewal.crt", data=cert)
        elif name != "ssh_new_path":
            self.fixture(profile)
        row = dict(scenario_id=name, start_time=time.time(), end_time="", src_role="client" if name != "ssh_new_path" else "bastion",
                   dst_role="proxy" if tls else "backend" if name == "ssh_new_path" else "bastion",
                   protocol="tls" if tls else "ssh", expected_rule=rule, ground_truth_label=label,
                   expected_behavior=name,
                   dst_port=443 if tls else 22 if name == "ssh_new_path" else 2223,
                   scenario_type="benign_maintenance" if label == "benign" else "abnormal", completed="false")
        count, rejected = 0, 0
        try:
            deadline = time.monotonic() + self.config["window_seconds"]
            while True:
                if tls:
                    trust = ["--cacert", "/tmp/dataset_renewal.crt"] if name == "tls_benign_renewal" else ["-k"]
                    exec_lab("client", "curl", "-fsS", *trust, "--max-time", "4", "--tls-max", "1.2",
                         "--ciphers", "ALL:@SECLEVEL=0", "--resolve", "proxy.topic4.lab:443:172.30.20.10",
                         "-o", "/dev/null", "https://proxy.topic4.lab/api/status", timeout=8)
                else:
                    self.ssh_action(name)
                    rejected += int(name == "ssh_bruteforce_like")
                count += 1
                if name == "ssh_bruteforce_like":
                    if count >= self.config["brute_force_attempts"]:
                        break
                    time.sleep(self.config["brute_force_interval"])
                else:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(self.config["scenario_interval"])
            row["completed"] = "true"
        finally:
            row["end_time"] = time.time()
            self.rows.append(row)
            self.write_scenario_manifest(row)
            write_manifest(self.manifests / "scenario_manifest.csv", self.rows)
            self.outcomes.append({"scenario_id": name, "attempts": count, "rejected_public_key_attempts": rejected,
                                  "timeout_attempts": self.ssh_timeouts[name],
                                  "completed": row["completed"]})
            if not tls and name != "ssh_new_path":
                self.fixture("stop")
            if tls:
                self.activate_tls("modern")
                self.enable_tls_background()
        print(f"Completed {name}: {count} attempts ({label})", flush=True)

    def cleanup(self):
        failures = []
        for operation in (self.stop_background,
                          lambda: self.fixture("stop") if self.firewall_added else None,
                          lambda: exec_lab("router", "iptables", "-D", *FIREWALL) if self.firewall_added else None,
                          lambda: self.activate_tls(self.original_profile) if self.original_profile else None,
                          lambda: exec_lab("client", "sh", "-c", "cat > /root/.ssh/known_hosts", data=self.previous_known_hosts) if self.previous_known_hosts is not None else None,
                          lambda: exec_lab("client", "rm", "-f", "/tmp/dataset_wrong_key", "/tmp/dataset_wrong_key.pub", "/tmp/dataset_known_hosts", "/tmp/dataset_modern.crt", "/tmp/dataset_renewal.crt") if self.client_ready else None,
                          lambda: docker("compose", "rm", "-s", "-f", "client") if self.client_ready and self.client_existed is False else None):
            try:
                operation()
            except Exception as error:
                failures.append(type(error).__name__)
        if failures:
            raise RuntimeError(f"Cleanup failed: {failures}; see recovery instructions")


def validate_config(config):
    if config.get("schema_version") != "lab-generation-v1":
        raise ValueError("Unsupported generation config")
    for key in ("warmup_seconds", "cooldown_seconds", "window_seconds", "gap_seconds",
                "background_http_interval", "background_ssh_interval", "scenario_interval", "brute_force_interval"):
        value = float(config[key])
        if not 0.2 <= value <= 3600:
            raise ValueError(f"{key} must be between 0.2 and 3600 seconds")
    if not isinstance(config["brute_force_attempts"], int) or not 6 <= config["brute_force_attempts"] <= 30:
        raise ValueError("Brute-force-like attempts must be 6..30 per run")
    if (not config["scenarios"] and not config.get("benign_only")) or len(set(config["scenarios"])) != len(config["scenarios"]) or not set(config["scenarios"]) <= set(SCENARIOS):
        raise ValueError("Invalid/duplicate scenario names")
    if config.get("benign_only") and config["scenarios"]:
        raise ValueError("benign_only cannot contain abnormal scenarios")
    for low, high in config.get("ssh_hold_ranges", [[0, 0]]):
        if not 0 <= low <= high <= 180:
            raise ValueError("SSH hold ranges must be bounded to 0..180 seconds")
    if not set(config.get("tls_versions", ["1.2"])) <= {"1.2", "1.3"}:
        raise ValueError("Unsupported TLS background version")
    if any(rate and not 256 <= rate <= 10000000 for rate in config.get("tls_rate_limits", [0])):
        raise ValueError("Invalid bounded TLS rate limit")
    if config.get("collection_profile") == "lab-v3-attacks":
        for field, low, high in (("password_attempts", 6, 30), ("scan_repetitions", 1, 4),
                                 ("tls_burst_concurrency", 1, 2), ("beacon_burst_size", 1, 4), ("tls_pattern_max_requests", 1, 80)):
            if type(config.get(field)) is not int or not low <= config[field] <= high:
                raise ValueError(f"{field} outside bounded lab limits")
        for field in ("password_guess_interval", "password_spray_interval", "scan_interval", "tls_burst_interval"):
            if not 0.25 <= config.get(field, 0) <= 30:
                raise ValueError(f"{field} outside bounded lab intervals")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/custom_dataset.json")
    parser.add_argument("--quick", action="store_true", help="Short smoke run; not research dataset")
    parser.add_argument("--parquet", action="store_true")
    args = parser.parse_args()
    if args.parquet:
        try:
            import pyarrow
        except ImportError:
            parser.error("--parquet requires pyarrow; CSV needs no third-party package")
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.quick:
        config.update(warmup_seconds=3, cooldown_seconds=2, window_seconds=2, gap_seconds=0.5,
                      scenario_interval=0.5, brute_force_attempts=6, brute_force_interval=0.25,
                      background_ssh_interval=2)
    generate(config, args.parquet, args.quick)


def generate(config, parquet=False, quick_sample=False, run_id=None, artifact_directory=None, verbose=False):
    validate_config(config)
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    artifact = Path(artifact_directory).resolve() if artifact_directory else ROOT / "data/lab_metadata/custom" / run_id
    if not artifact.resolve().is_relative_to((ROOT / "data/lab_metadata").resolve()):
        raise ValueError("Run artifacts must stay inside data/lab_metadata")
    manifests = artifact / "manifests" if artifact_directory else ROOT / "data/manifests/custom" / run_id
    lock_path = ROOT / "data/lab_metadata/custom/.generation.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_file = lock_path.open("x", encoding="utf-8")
    except FileExistsError:
        raise RuntimeError("Another/interrupted generator holds .generation.lock; see recovery instructions") from None
    lock_file.write(str(os.getpid()))
    lock_file.close()
    try:
        artifact.mkdir(parents=True)
    except BaseException:
        lock_path.unlink(missing_ok=True)
        raise
    # New profile reuses the same snapshot/join/validator pipeline.
    # Import lazily so old campaigns keep their existing harness.
    if config.get("collection_profile") == "lab-v3-attacks":
        from src.data_generation.attacks import AttackDatasetHarness
        harness = AttackDatasetHarness(config, artifact, manifests)
    elif config.get("collection_profile") == "lab-v2":
        from src.data_generation.scenarios import DatasetHarnessV2
        harness = DatasetHarnessV2(config, artifact, manifests)
    else:
        harness = Harness(config, artifact, manifests)
    passed = False
    from src.data_generation.runtime import DatasetProgress
    progress = DatasetProgress(harness, verbose)
    try:
        (artifact / "generation_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        progress.phase("PREPARE: checking services, sensor and lab fixtures")
        harness.prepare()
        start = time.time()
        harness.start_background()
        progress.background_routes()
        progress.phase(f"WARMUP: benign background only, {config['warmup_seconds']:.0f}s")
        time.sleep(config["warmup_seconds"])
        for scenario in config["scenarios"]:
            progress.case(scenario)
            try:
                harness.run_scenario(scenario)
            except BaseException:
                progress.say(f"CASE FAILED {scenario}; round will not be published")
                raise
            progress.say(f"CASE DONE {scenario}")
            progress.phase(f"GAP: benign background continues, {config['gap_seconds']:.0f}s")
            time.sleep(config["gap_seconds"])
        progress.phase(f"COOLDOWN: benign background continues, {config['cooldown_seconds']:.0f}s")
        time.sleep(config["cooldown_seconds"])
        progress.phase("BACKGROUND STOP: waiting for in-flight requests to finish")
        harness.stop_background()
        end = time.time()
        for name, src, dst, proto, port in (("background_http", "web-frontend", "backend", "tcp", 8000),
            ("background_db", "backend", "db", "tcp", 5432), ("background_ssh_outer", "client", "bastion", "ssh", 2222),
            ("background_ssh_inner", "bastion", "web-frontend", "ssh", 22)):
            row = dict(scenario_id=name, start_time=start, end_time=end, src_role=src, dst_role=dst,
                       protocol=proto, expected_rule="", ground_truth_label="benign", dst_port=port,
                       expected_behavior="authorized_background",
                       scenario_type="background", completed="true")
            harness.rows.append(row)
            harness.write_scenario_manifest(row)
        for index, (tls_start, tls_end) in enumerate(harness.tls_benign_intervals):
            row = dict(scenario_id=f"background_tls_{index}", start_time=tls_start, end_time=tls_end,
                       src_role="client", dst_role="proxy", protocol="tls", expected_rule="",
                       expected_behavior="trusted_modern_tls", ground_truth_label="benign", dst_port=443,
                       scenario_type="background", completed="true")
            harness.rows.append(row)
            harness.write_scenario_manifest(row)
        write_manifest(manifests / "scenario_manifest.csv", harness.rows)
        # Collection has ended; flush once, then immediately restore live Zeek.
        progress.phase("SENSOR: flush/restart Zeek, then snapshot metadata logs")
        docker("compose", "restart", "zeek")
        docker("compose", "up", "-d", "--no-deps", "--wait", "zeek")
        snapshot_logs(artifact / "zeek", start, end)
        progress.phase("JOIN: session + TLS/SSH/X509 + manifest; validate metadata and labels")
        summary = label_dataset(artifact / "zeek", manifests / "scenario_manifest.csv",
                                ROOT / "experiments/lab_roles.json", artifact, run_id, parquet)
        (artifact / "scenario_outcomes.json").write_text(json.dumps(harness.outcomes, indent=2), encoding="utf-8")
        background = {"counts": dict(harness.background_counts), "failures": dict(harness.background_failures),
                      "start_time": start, "end_time": end, "continuous": True,
                      "scenario_coverage": {row["scenario_id"]: sum(event["success"] and event["kind"] == "http_internal"
                          and event["start_time"] < row["end_time"] and event["end_time"] > row["start_time"]
                          for event in harness.background_events) for row in harness.rows if row["scenario_type"] == "abnormal"}}
        (artifact / "background_events.json").write_text(json.dumps(harness.background_events, indent=2), encoding="utf-8")
        (artifact / "background_summary.json").write_text(json.dumps(background, indent=2), encoding="utf-8")
        if not all(harness.background_counts[kind] for kind in ("http_internal", "ssh_authorized")):
            raise RuntimeError("A benign background stream produced no successful actions")
        if harness.background_failures:
            raise RuntimeError("Background failures occurred; dataset requires review")
        if not all(background["scenario_coverage"].values()):
            raise RuntimeError("A scenario window has no concurrent benign HTTP background; increase window_seconds")
        required_scenarios = set(config["scenarios"]) | {"background_http", "background_db", "background_ssh_outer", "background_ssh_inner"}
        missing_required = required_scenarios & set(summary["missing_scenarios"])
        # v2 may emit one manifest row per target/port. Check every child,
        # not just the parent name in generation_config.
        if config.get("collection_profile") in {"lab-v2", "lab-v3-attacks"}:
            missing_required |= {name for name in summary["missing_scenarios"]
                                 if any(name == scenario or name.startswith(scenario + "_") for scenario in config["scenarios"])}
        if missing_required:
            raise RuntimeError(f"No labeled sessions for required scenarios: {sorted(missing_required)}")
        if config.get("collection_profile") in {"lab-v2", "lab-v3-attacks"} and config.get("require_extended_metadata", True):
            extended = summary.get("extended_metadata", {})
            if not extended.get("packet_rows") or not extended.get("tls_extension_rows"):
                raise RuntimeError("v2 sensor emitted no packet/TLS extension metadata; round excluded, inspect sensor")
        print(f"PASS: {summary['label_counts']}; quarantine={summary['quarantined_count']}", flush=True)
        print(f"Dataset: {artifact}", flush=True)
        passed = True
    finally:
        try:
            progress.phase("CLEANUP: restore temporary TLS/SSH fixtures and firewall rules")
            harness.cleanup()
            state = {"completed": passed, "cleanup_passed": True, "run_id": run_id,
                     "manifest": str(manifests / "scenario_manifest.csv"),
                     "quick_sample": quick_sample}
            (artifact / "run_status.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
            if passed:
                checksums = {str(p.relative_to(ROOT)): checksum(p) for base in (artifact, manifests)
                             for p in base.rglob("*") if p.is_file() and p.name != "checksums.json"}
                (artifact / "checksums.json").write_text(json.dumps(checksums, indent=2), encoding="utf-8")
        finally:
            progress.close()
            lock_path.unlink(missing_ok=True)

    return artifact


if __name__ == "__main__":
    main()
