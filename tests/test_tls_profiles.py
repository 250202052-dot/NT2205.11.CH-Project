"""Test one proxy sequentially. Save certificate/scenario metadata, never keys or bodies."""
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.data_generation.runtime import docker
PROFILES = {
    "modern": "baseline_pinned_certificate",
    "weak": "tls_policy_violation",
    "weak-cert": "certificate_rsa_1024",
    "expired-cert": "certificate_expired",
    "wrong-host": "certificate_hostname_mismatch",
    "replaced-cert": "unexpected_self_signed_identity",
}


def main():
    original = docker("compose", "exec", "-T", "proxy", "printenv", "TLS_PROFILE").stdout.decode().strip()
    client_existed = bool(docker("compose", "ps", "-a", "-q", "client").stdout.strip())
    records = []
    columns = ["scenario_id", "start_ts", "end_ts", "profile", "expected_condition",
               "src_role", "dst_role", "certificate_sha256", "spki_sha256",
               "verification_exit", "test_result"]
    def activate(profile):
        env = dict(os.environ, TLS_PROFILE=profile)
        docker("compose", "up", "-d", "--no-deps", "--wait", "--wait-timeout", "45", "proxy", env=env)
    def public_cert(profile):
        return docker("compose", "exec", "-T", "proxy", "cat", f"/etc/nginx/tls/{profile}/server.crt").stdout
    def trust(certificate):
        docker("compose", "exec", "-T", "client", "sh", "-c", "cat > /tmp/profile-trust.crt", data=certificate)
    def curl(*options, check=True):
        return docker("compose", "exec", "-T", "client", "curl", "-fsS", "--max-time", "8",
                      "--tls-max", "1.2", "--cacert", "/tmp/profile-trust.crt",
                      "--resolve", "proxy.topic4.lab:443:172.30.20.10", *options,
                      "https://proxy.topic4.lab/api/status", check=check)
    try:
        docker("compose", "--profile", "test", "up", "-d", "--wait", "client")
        activate("modern")
        baseline = public_cert("modern")
        baseline_key = docker("compose", "exec", "-T", "proxy", "openssl", "x509",
                              "-in", "/etc/nginx/tls/modern/server.crt", "-pubkey", "-noout").stdout
        # X.509 logs are cached by fingerprint; start a fresh sensor for this test.
        docker("compose", "restart", "zeek")
        docker("compose", "up", "-d", "--wait", "zeek")
        for profile, expected in PROFILES.items():
            activate(profile)
            start = time.time()
            certificate = public_cert(profile)
            trust(baseline if profile == "replaced-cert" else certificate)
            result = curl(check=False)
            error = result.stderr.decode(errors="replace").lower()
            if profile == "modern":
                assert result.returncode == 0, error
            elif profile == "weak":
                assert result.returncode in (35, 60), error
            elif profile == "weak-cert":
                assert result.returncode in (35, 60) and ("key too weak" in error or "key too small" in error), error
            elif profile == "expired-cert":
                assert result.returncode == 60 and "expired" in error, error
            elif profile == "wrong-host":
                assert result.returncode == 60 and ("subject name" in error or "alternative" in error), error
            elif profile == "replaced-cert":
                assert result.returncode == 60 and "self-signed" in error, error
            # Insecure access is an explicit collection step; success != trusted certificate.
            permissive = curl("-k", "--ciphers", "ALL:@SECLEVEL=0")
            assert json.loads(permissive.stdout)["db_result"] == 1
            pubkey = docker("compose", "exec", "-T", "proxy", "openssl", "x509",
                            "-in", f"/etc/nginx/tls/{profile}/server.crt", "-pubkey", "-noout").stdout
            if profile == "replaced-cert":
                assert pubkey != baseline_key, "Replacement needs a different key"
                trust(certificate)
                assert curl().returncode == 0, "Replacement should work if explicitly trusted"
            if profile in ("weak", "weak-cert"):
                details = docker("compose", "exec", "-T", "proxy", "openssl", "x509",
                                 "-in", f"/etc/nginx/tls/{profile}/server.crt", "-text", "-noout").stdout
                assert b"1024 bit" in details
            fingerprint = docker("compose", "exec", "-T", "proxy", "openssl", "x509",
                                 "-in", f"/etc/nginx/tls/{profile}/server.crt", "-noout", "-fingerprint", "-sha256").stdout.decode().strip().split("=", 1)[1]
            key_der = docker("compose", "exec", "-T", "proxy", "openssl", "pkey",
                             "-pubin", "-outform", "DER", data=pubkey).stdout
            records.append(dict(zip(columns, [str(uuid.uuid4()), start, time.time(), profile, expected,
                                               "test-client", "proxy", fingerprint,
                                               hashlib.sha256(key_der).hexdigest(), result.returncode, "CLIENT_PASS"])))
            print(f"PASS: {profile} (strict client exit={result.returncode})", flush=True)
        # Flush certificate metadata, restoring capture afterwards.
        docker("compose", "restart", "zeek")
        docker("compose", "up", "-d", "--wait", "zeek")
        certificate_logs = []
        tls_logs = []
        notice_logs = []
        for path in (ROOT / "data/lab_metadata/zeek").glob("ssl*.log"):
            tls_logs.extend(json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())
        for path in (ROOT / "data/lab_metadata/zeek").glob("x509*.log"):
            certificate_logs.extend(json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())
        for path in (ROOT / "data/lab_metadata/zeek").glob("notice*.log"):
            notice_logs.extend(json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())
        for record in records:
            expected_fingerprint = record["certificate_sha256"].replace(":", "").lower()
            observed = [r for r in certificate_logs if record["start_ts"] - 1 <= r.get("ts", 0) <= record["end_ts"] + 1
                        and r.get("fingerprint", "").lower() == expected_fingerprint]
            assert observed, f'No fresh Zeek X.509 metadata for {record["profile"]}'
            assert any(r.get("spki_sha256") == record["spki_sha256"] for r in observed), "SPKI mismatch"
            if record["profile"] == "expired-cert":
                assert any(r.get("certificate.not_valid_after", float("inf")) < record["start_ts"] for r in observed)
            if record["profile"] == "weak-cert":
                assert any(r.get("certificate.key_length") == 1024 for r in observed)
            sessions = [r for r in tls_logs if record["start_ts"] - 1 <= r.get("ts", 0) <= record["end_ts"] + 1 and r.get("established")]
            assert sessions, f'No established TLS session for {record["profile"]}'
            assert any(all(r.get(field) for field in ("ja3", "ja3s", "ja4", "ja4s")) for r in sessions), "Missing TLS fingerprints"
            expected_rules = {
                "modern": set(),
                "weak": {"TLS_CIPHER_NOT_ALLOWED", "TLS_RSA_KEY_TOO_SMALL"},
                "weak-cert": {"TLS_RSA_KEY_TOO_SMALL"},
                "expired-cert": {"TLS_CERT_EXPIRED"},
                "wrong-host": {"TLS_CERT_HOSTNAME_MISMATCH"},
                "replaced-cert": {"TLS_CERT_UNTRUSTED"},
            }[record["profile"]]
            actual_rules = {rule for r in sessions for rule in r.get("policy_violations", [])}
            assert expected_rules <= actual_rules, f'Missing rules: {record["profile"]}: {expected_rules - actual_rules}'
            if record["profile"] == "modern":
                assert not actual_rules - {"TLS_CERT_UNTRUSTED"}, f"Modern crypto false positive: {actual_rules}"
            session_uids = {r["uid"] for r in sessions}
            notice_rules = {r.get("rule_id") for r in notice_logs if r.get("uid") in session_uids}
            assert expected_rules <= notice_rules, "Missing correlated rule notice"
            if record["profile"] == "weak":
                assert any(r.get("cipher") == "TLS_RSA_WITH_AES_128_CBC_SHA" for r in sessions)
            else:
                assert any("ECDHE" in r.get("cipher", "") for r in sessions)
            record["test_result"] = "PASS"
        print("PASS: fresh certificate metadata, SPKI, JA3/JA4 and correlated rule notices for all profiles", flush=True)
    finally:
        try:
            activate(original)
        finally:
            if not client_existed:
                docker("compose", "rm", "-s", "-f", "client")
            if records:
                directory = ROOT / "data" / "manifests"
                directory.mkdir(parents=True, exist_ok=True)
                path = directory / f"tls_profiles_{time.time_ns()}.csv"
                with path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=columns)
                    writer.writeheader()
                    writer.writerows(records)
                print(f"Scenario metadata: {path}", flush=True)


if __name__ == "__main__":
    main()
