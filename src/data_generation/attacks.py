"""Attack-rich lab profile using Nmap/OpenSSH/curl against fixed lab assets.

These are executed traffic fixtures, not confirmed compromise. Keep labels
from manifest + bounded execution evidence; network metadata cannot show
SSH username/password or prove account-level spraying on its own.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import time
import xml.etree.ElementTree as ET

from src.data_generation.scenarios import DatasetHarnessV2
from src.data_generation.runtime import exec_lab
from src.data_generation.generator import ROOT
from src.data_generation.generator import SCENARIOS

CATALOG = {
    "ssh_password_guessing": ("T1110.001", "OpenSSH", "repeated_failed_password_auth"),
    "ssh_password_spraying": ("T1110.003", "OpenSSH", "failed_password_auth_across_lab_accounts"),
    "tls_beacon_jitter": ("T1573", "curl", "controlled_tls_timing_not_c2_payload"),
    "tls_beacon_burst": ("T1573", "curl", "controlled_tls_timing_not_c2_payload"),
    "tls_connection_burst": ("", "curl", "bounded_connection_burst_not_proven_dos"),
    "nmap_tcp_connect_scan": ("T1046", "Nmap", "tcp_connect_port_scan"),
    "nmap_ssh_horizontal_scan": ("T1046", "Nmap", "ssh_port_discovery_across_lab_hosts"),
    "ssh_lateral_sequence": ("T1021.004", "OpenSSH", "authorized_key_new_paths_not_compromise"),
    "tls_interception_fixture": ("T1557", "Nginx", "controlled_interception_route_not_external_aitm"),
}
for variant, original in {
    "ssh_password_guessing_slow": "ssh_password_guessing",
    "ssh_password_spraying_slow": "ssh_password_spraying",
    "ssh_lateral_variable": "ssh_lateral_sequence",
    "tls_beacon_slow": "tls_beacon_jitter",
    "tls_beacon_variable": "tls_beacon_jitter",
    "tls_connection_burst_variable": "tls_connection_burst",
    "tls_interception_sameport": "tls_interception_fixture",
}.items():
    CATALOG[variant] = CATALOG[original]
SCAN_TARGETS = {"proxy": "172.30.20.10", "backend": "172.30.30.20", "db": "172.30.30.30"}


def nmap_command(name):
    """Only TCP connect: no raw scan, NSE, version probes or arbitrary targets."""
    common = ["nmap", "-sT", "-Pn", "-n", "--max-rate", "10", "--max-retries", "1", "--host-timeout", "30s", "-oX", "-"]
    if name == "nmap_tcp_connect_scan":
        return common + ["-p", "4443,4450-4455", "172.30.20.10"]
    if name == "nmap_ssh_horizontal_scan":
        return common + ["-p", "22", "172.30.30.20", "172.30.30.30"]
    raise ValueError("Unknown/out-of-scope scan")


def nmap_evidence(output, targets):
    """Keep port-state counts only; never persist raw Nmap XML/banner output."""
    root = ET.fromstring(output)
    expected = {SCAN_TARGETS[role] for role, _ in targets}
    addresses = {a.attrib["addr"] for host in root.findall("host") for a in host.findall("address") if a.get("addrtype") == "ipv4"}
    finished = root.find("runstats/finished")
    if addresses != expected or finished is None or finished.get("exit") != "success":
        raise RuntimeError("Nmap did not complete the expected lab targets")
    states = []
    for host in root.findall("host"):
        address = next(a.attrib["addr"] for a in host.findall("address") if a.get("addrtype") == "ipv4")
        needed = sum(SCAN_TARGETS[role] == address for role, _ in targets)
        reported = len(host.findall("ports/port")) + sum(int(node.get("count", 0)) for node in host.findall("ports/extraports"))
        if host.get("timedout") == "true" or reported != needed:
            raise RuntimeError("Nmap returned partial/timed-out port coverage")
        for node in host.findall("ports/port/state"):
            states.append(node.get("state"))
    return {"completed_hosts": len(addresses), "explicit_port_states": {state: states.count(state) for state in set(states)},
            "raw_scan_output_retained": False}


class AttackDatasetHarness(DatasetHarnessV2):
    def __init__(self, *args):
        super().__init__(*args)
        self.password_script = (ROOT / "docker/bastion/dataset-password-sshd.sh").read_bytes()
        self.password_owned = False
        self.attack_extra_rules = []

    def prepare(self):
        # Fail before changing services if the client image lacks Nmap.
        super().prepare()
        if exec_lab("client", "nmap", "--version", check=False).returncode:
            raise ValueError("Build client with Nmap after stopping collection: docker compose build client")
        if exec_lab("bastion", "test", "-e", "/tmp/topic4-dataset-password-ssh", check=False).returncode == 0:
            raise ValueError("Interrupted password fixture exists; recover it first")
        # Allow only port 22 discovery on these two existing lab servers.
        for role in ("backend", "db"):
            rule = ["FORWARD", "-s", "172.30.10.10", "-d", SCAN_TARGETS[role], "-p", "tcp", "--dport", "22",
                    "-m", "comment", "--comment", "topic4-attack-dataset", "-j", "ACCEPT"]
            if exec_lab("router", "iptables", "-C", *rule, check=False).returncode == 0:
                raise ValueError("Interrupted attack firewall exists; recover it first")
            exec_lab("router", "iptables", "-I", "FORWARD", "1", *rule[1:])
            self.attack_extra_rules.append(rule)

    def row(self, name, *args, **kwargs):
        row = super().row(name, *args, **kwargs)
        row["fixture_version"] = "lab-attack-fixtures-v3"
        if name in CATALOG:
            technique, tool, scope = CATALOG[name]
            row.update(attack_mapping=technique, execution_tool=tool, evidence_scope=scope)
        return row

    def run_scenario(self, name):
        if name in {"ssh_lateral_variable", "ssh_benign_lateral_variable"}:
            return self.variable_lateral(name)
        if name in {"tls_beacon_slow", "tls_beacon_variable", "tls_connection_burst_variable",
                    "tls_benign_periodic", "tls_benign_burst", "tls_interception_sameport",
                    "tls_policy_regression"}:
            return self.variable_tls(name)
        if name == "ssh_benign_password_retry":
            return self.password_attempts(name)
        if name.startswith("ssh_password_"):
            return self.password_attempts(name)
        if name.startswith("nmap_"):
            return self.nmap_scan(name)
        if name in {"tls_beacon_jitter", "tls_beacon_burst", "tls_connection_burst"}:
            return self.tls_pattern(name)
        return super().run_scenario(name)

    def password_attempts(self, name):
        """Tạo tài khoản tạm, thử password sai, chỉ lưu số lần bị từ chối."""
        self.password_owned = True
        exec_lab("bastion", "sh", "-s", "--", "start", data=self.password_script, timeout=25)
        known = exec_lab("bastion", "cat", "/tmp/topic4-dataset-password-ssh/known_hosts").stdout
        exec_lab("client", "sh", "-c", "cat > /tmp/dataset_known_hosts", data=known)
        # Askpass reads a temporary wrong-password file. No credential in
        # process argv, manifest, exceptions or dataset artifacts.
        askpass = b'#!/bin/sh\ncat /tmp/topic4_attack_wrong_password\n'
        exec_lab("client", "sh", "-c", "umask 077; cat > /tmp/topic4_attack_askpass; chmod 700 /tmp/topic4_attack_askpass", data=askpass)
        same_wrong = secrets.token_hex(12)
        spraying = name.startswith("ssh_password_spraying")
        benign_retry = name == "ssh_benign_password_retry"
        accounts = ["topic4spray1", "topic4spray2", "topic4spray3"] if spraying else ["topic4guess"]
        attempts, failures, successes = 0, 0, 0
        row = self.row(name, SCENARIOS[name][1], "ssh", "bastion", 2223)
        attempt_count = 3 if benign_retry else self.config.get("password_attempts", 18)
        delay = self.config.get("password_spray_interval", 2) if spraying else self.config.get("password_guess_interval", 0.5)
        if name.endswith("_slow"):
            delay = 10 if spraying else 6
        try:
            for index in range(attempt_count):
                correct_attempt = benign_retry and index == attempt_count - 1
                if correct_attempt:
                    credential = exec_lab("bastion", "cat", "/tmp/topic4-dataset-password-ssh/authorized_password").stdout
                else:
                    credential = (same_wrong if spraying else secrets.token_hex(12)).encode()
                # Secret only enters an ephemeral container file, never logs/artifacts.
                exec_lab("client", "sh", "-c", "umask 077; cat > /tmp/topic4_attack_wrong_password", data=credential)
                account = accounts[index % len(accounts)]
                result = exec_lab("client", "env", "SSH_ASKPASS=/tmp/topic4_attack_askpass", "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:0",
                    "timeout", "-s", "KILL", "15", "ssh", "-F", "/dev/null", "-p", "2223",
                    "-o", "BatchMode=no", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                    "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=/tmp/dataset_known_hosts", f"{account}@172.30.20.20", "true",
                    data=b"", check=False, timeout=25)
                if correct_attempt and result.returncode != 0:
                    raise RuntimeError("Benign SSH retry did not finish with authorized authentication")
                if not correct_attempt and (result.returncode != 255 or b"Permission denied" not in result.stderr or b"(password)" not in result.stderr):
                    raise RuntimeError("Password fixture did not produce verified auth rejection")
                attempts += 1
                failures += int(not correct_attempt)
                successes += int(correct_attempt)
                time.sleep(delay)
            time.sleep(max(3, self.config["background_http_interval"] * 2))
            row["completed"] = "true"
        finally:
            self.persist(row)
            self.outcomes.append(dict(scenario_id=name, completed=row["completed"], attempts=attempts,
                evidence={"failed_password_auth": failures, "distinct_lab_accounts": len(accounts),
                    "successful_password_auth": successes,
                    "same_candidate_across_accounts": spraying, "credential_retained": False,
                    "account_names_retained": False, "network_only_can_prove_spraying": False}))
            self.stop_password_fixture()

    def variable_lateral(self, name):
        targets = ["backend", "db"]
        self.workload_rng.shuffle(targets)
        for target in targets:
            row = self.row(name, SCENARIOS[name][1], "ssh", target, 22)
            row.update(scenario_id=f"{name}_{target}", src_role="bastion")
            attempts = 0
            try:
                for _ in range(self.workload_rng.randint(4, 7)):
                    exec_lab("client", "timeout", "-s", "KILL", "15", "ssh", target, "true", timeout=30)
                    attempts += 1
                    time.sleep(self.workload_rng.uniform(1, 4))
                time.sleep(3)
                row["completed"] = "true"
            finally:
                self.persist(row)
                self.outcomes.append(dict(scenario_id=row["scenario_id"], completed=row["completed"],
                    attempts=attempts, evidence={"authorized_lab_key": True,
                    "scripted_path": f"client->bastion->{target}", "compromise_simulated": False,
                    "authorized_administration": SCENARIOS[name][1] == "benign"}))

    def wait_tls_profile(self, ca_path):
        """Nginx reload is asynchronous; verify the expected trust before labeling."""
        for _ in range(10):
            result = exec_lab("client", "curl", "-fsS", "--cacert", ca_path, "--max-time", "3",
                "--tls-max", "1.2", "--ciphers", "ALL:@SECLEVEL=0", "--resolve",
                "proxy.topic4.lab:4443:172.30.20.10", "-o", "/dev/null",
                "https://proxy.topic4.lab:4443/api/status", check=False, timeout=8)
            if result.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError("Expected TLS fixture did not become ready; round excluded")

    def variable_tls(self, name):
        profile, label, _ = SCENARIOS[name]
        self.tls_fixture("modern")
        self.wait_tls_profile("/tmp/dataset_modern.crt")
        # Keep a labeled normal reference for certificate/policy continuity.
        baseline = self.row("tls_benign_periodic", "benign", "tls", "proxy", 4443)
        baseline["scenario_id"] = name + "_baseline"
        baseline["expected_behavior"] = "tls_benign_endpoint_baseline"
        self.tls_request(4443, verify=True)
        time.sleep(3)
        baseline["completed"] = "true"
        self.persist(baseline)
        ca_path = "/tmp/dataset_modern.crt"
        if name == "tls_interception_sameport":
            self.tls_fixture(profile)
            ca = exec_lab("proxy", "cat", "/tmp/topic4-dataset-tls-v2/ca.crt").stdout
            exec_lab("client", "sh", "-c", "cat > /tmp/dataset_interception_ca.crt", data=ca)
            ca_path = "/tmp/dataset_interception_ca.crt"
        elif name == "tls_policy_regression":
            self.tls_fixture("weak")
            cert = exec_lab("proxy", "cat", "/tmp/topic4-dataset-tls-v2/weak.crt").stdout
            exec_lab("client", "sh", "-c", "cat > /tmp/dataset_weak_ca.crt", data=cert)
            ca_path = "/tmp/dataset_weak_ca.crt"
        self.wait_tls_profile(ca_path)

        row = self.row(name, label, "tls", "proxy", 4443)
        duration = 120 if name in {"tls_beacon_slow", "tls_benign_periodic"} else 60
        deadline = time.monotonic() + duration
        attempts = 0
        try:
            while time.monotonic() < deadline and attempts < 80:
                burst = self.workload_rng.randint(2, 4) if "burst" in name else 1
                for _ in range(burst):
                    tool = self.workload_rng.choice(("curl", "openssl"))
                    if tool == "curl":
                        exec_lab("client", "curl", "-fsS", "--cacert", ca_path, "--max-time", "8",
                            "--tls-max", "1.2", "--ciphers", "ALL:@SECLEVEL=0", "--resolve",
                            "proxy.topic4.lab:4443:172.30.20.10", "-o", "/dev/null",
                            "https://proxy.topic4.lab:4443/api/status", timeout=15)
                    else:
                        exec_lab("client", "timeout", "-s", "KILL", "10", "openssl", "s_client",
                            "-connect", "172.30.20.10:4443", "-servername", "proxy.topic4.lab",
                            "-tls1_2", "-cipher", "ALL:@SECLEVEL=0", "-CAfile", ca_path,
                            "-verify_hostname", "proxy.topic4.lab", "-verify_return_error", "-brief",
                            data=b"", timeout=15)
                    attempts += 1
                    if burst > 1:
                        time.sleep(self.workload_rng.uniform(0.1, 0.4))
                if name in {"tls_beacon_slow", "tls_benign_periodic"}:
                    delay = self.workload_rng.uniform(10, 20)
                elif "burst" in name:
                    delay = self.workload_rng.uniform(1, 5)
                else:
                    delay = self.workload_rng.uniform(2, 12)
                time.sleep(min(delay, max(0, deadline - time.monotonic())))
            time.sleep(3)
            row["completed"] = "true"
        finally:
            self.persist(row)
            self.outcomes.append(dict(scenario_id=name, attempts=attempts, completed=row["completed"],
                evidence={"client_port": 4443, "client_tools": ["curl", "openssl"],
                    "scheduled_seconds": duration, "actual_payload_semantics_observed": False,
                    "certificate_substitution_fixture": name == "tls_interception_sameport",
                    "policy_regression_not_proven_network_downgrade": name == "tls_policy_regression",
                    "no_real_malware": True}))
            self.tls_fixture("modern")

    def stop_password_fixture(self):
        if self.password_owned:
            exec_lab("bastion", "sh", "-s", "--", "stop", data=self.password_script, timeout=25)
            self.password_owned = False
        if self.client_ready:
            exec_lab("client", "rm", "-f", "/tmp/topic4_attack_askpass", "/tmp/topic4_attack_wrong_password")

    def cleanup(self):
        try:
            self.stop_password_fixture()
            if self.client_ready:
                exec_lab("client", "rm", "-f", "/tmp/dataset_interception_ca.crt", "/tmp/dataset_weak_ca.crt")
        finally:
            # Restore base listeners/firewall even if disposable-secret cleanup fails.
            super().cleanup()

    def nmap_scan(self, name):
        """Quét đúng host/port trong lab; kiểm tra XML rồi bỏ output gốc."""
        targets = [("proxy", port) for port in (4443, *range(4450, 4456))] if name == "nmap_tcp_connect_scan" else [("backend", 22), ("db", 22)]
        started = time.time()
        rows = []
        for role, port in targets:
            row = self.row(name, "attack_behavior", "tcp", role, port, dst_ip=SCAN_TARGETS[role])
            row.update(scenario_id=f"{name}_{role}_{port}", start_time=started)
            rows.append(row)
        evidence, count = {}, 0
        try:
            for _ in range(self.config.get("scan_repetitions", 3)):
                result = exec_lab("client", *nmap_command(name), timeout=45)
                evidence = nmap_evidence(result.stdout, targets)
                count += 1
                time.sleep(self.config.get("scan_interval", 1))
            time.sleep(max(3, self.config["background_http_interval"] * 2))
            for row in rows:
                row["completed"] = "true"
        finally:
            for row in rows:
                self.persist(row)
            self.outcomes.append(dict(scenario_id=name, completed=all(r["completed"] == "true" for r in rows),
                scan_executions=count, evidence=evidence, max_probes_per_second=10))

    def tls_pattern(self, name):
        """Tạo nhịp/burst HTTPS có giới hạn trong khi normal vẫn chạy."""
        # Strong certificate/cipher for every pattern: intent isn't inferable
        # from TLS weakness. Same endpoint/tool as benign control scenarios.
        self.tls_fixture("modern")
        row = self.row(name, "attack_behavior", "tls", "proxy", 4443)
        count = 0
        try:
            deadline = time.monotonic() + self.config["window_seconds"]
            while True:
                if name == "tls_connection_burst":
                    # At most two outstanding requests, bounded finite burst.
                    workers = self.config.get("tls_burst_concurrency", 2)
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        results = list(pool.map(lambda _: self.tls_request(4443, verify=True), range(workers)))
                    count += len(results)
                    delay = self.config.get("tls_burst_interval", 0.5)
                else:
                    burst = self.config.get("beacon_burst_size", 3) if name == "tls_beacon_burst" else 1
                    for _ in range(burst):
                        self.tls_request(4443, verify=True)
                        count += 1
                        if burst > 1:
                            time.sleep(0.25)
                    delay = self.config.get("beacon_interval", 2) * self.workload_rng.uniform(0.5, 1.5)
                if time.monotonic() >= deadline or count >= self.config.get("tls_pattern_max_requests", 80):
                    break
                time.sleep(delay)
            time.sleep(max(3, self.config["background_http_interval"] * 2))
            row["completed"] = "true"
        finally:
            self.persist(row)
            self.outcomes.append(dict(scenario_id=name, attempts=count, completed=row["completed"],
                evidence={"strong_tls_verified": True, "authorized_schedule": True, "payload_semantics_observed": False,
                    "pattern": name, "max_concurrency": self.config.get("tls_burst_concurrency", 2) if name == "tls_connection_burst" else 1,
                    "no_real_malware": True, "dos_impact_proven": False}))

    def cleanup(self):
        failures = []
        try:
            self.stop_password_fixture()
        except Exception:
            failures.append("password_fixture")
        for rule in reversed(self.attack_extra_rules):
            try:
                exec_lab("router", "iptables", "-D", *rule)
            except Exception:
                failures.append("attack_firewall")
        super().cleanup()
        if failures:
            raise RuntimeError(f"Attack cleanup failed: {failures}")
