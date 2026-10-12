"""Gọi Docker với timeout và hiển thị tiến độ thu metadata trên terminal.

Không in command/output nhạy cảm. IP hiển thị là endpoint theo topology;
địa chỉ thực trong Zeek có thể khác do router NAT.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]


class LabCommandTimeout(RuntimeError):
    """Thông báo timeout ngắn, không đưa command/output nhạy cảm vào lỗi."""


def docker(*args, data=None, check=True, env=None, timeout=150):
    try:
        result = subprocess.run(["docker", *args], cwd=ROOT, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        # subprocess chỉ dừng Docker CLI, không bảo đảm dừng process bên trong.
        # SSH fixture dùng thêm `timeout` ở container để tự kết thúc process đó.
        raise LabCommandTimeout(f"Docker {args[0]} exceeded {timeout} seconds") from None
    if check and result.returncode:
        # Commands may deal with endpoint keys or application bodies. Do not
        # expose captured output in errors; only command name and exit status.
        raise RuntimeError(f"Docker {args[0]} failed (exit {result.returncode})")
    return result


def exec_lab(service, *args, **kwargs):
    return docker("compose", "exec", "-T", service, *args, **kwargs)


def trust_hosts():
    entries = []
    for service, host, path in (
        ("bastion", "[172.30.20.20]:2222", "/config/ssh_host_keys/ssh_host_ed25519_key.pub"),
        ("web-frontend", "172.30.30.10", "/etc/ssh/hostkeys/ssh_host_ed25519_key.pub"),
        ("backend", "172.30.30.20", "/etc/ssh/hostkeys/ssh_host_ed25519_key.pub"),
        ("db", "172.30.30.30", "/etc/ssh/hostkeys/ssh_host_ed25519_key.pub"),
    ):
        parts = exec_lab(service, "cat", path).stdout.decode().split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise ValueError("Unexpected public host-key format")
        entries.append(f"{host} {parts[0]} {parts[1]}")
    exec_lab("client", "sh", "-c", "cat > /root/.ssh/known_hosts && chmod 600 /root/.ssh/known_hosts",
             data=("\n".join(entries) + "\n").encode())


# Hiển thị tiến độ trên terminal; không ghi thêm file.
LOCAL_TZ = timezone(timedelta(hours=7))


def case_endpoints(name, roles, profile):
    def endpoint(src, dst, ports, protocol):
        return f"src={src}({','.join(roles[src])}) -> dst={dst}({','.join(roles[dst])}):{ports} | {protocol}"
    if name in {"ssh_lateral_sequence", "ssh_lateral_variable", "ssh_benign_lateral_variable"}:
        return "; ".join(endpoint("bastion", dst, "22", "SSH via ProxyJump") for dst in ("backend", "db"))
    if name == "ssh_new_path":
        return endpoint("bastion", "backend", "22", "SSH via ProxyJump")
    if name == "nmap_ssh_horizontal_scan":
        return "; ".join(endpoint("client", dst, "22", "TCP connect scan") for dst in ("backend", "db"))
    if name.startswith("nmap_") or name.startswith("l3_"):
        ports = "4443,4450-4455" if name.startswith("nmap_") else "4450-4455"
        return endpoint("client", "proxy", ports, "TCP connect scan")
    if name.startswith("ssh_"):
        return endpoint("client", "bastion", "2223", "SSH")
    port = "4444" if name == "tls_interception_fixture" else "4443" if profile in {"lab-v2", "lab-v3-attacks"} else "443"
    result = endpoint("client", "proxy", port, "TLS")
    if name == "tls_interception_fixture":
        result += "; upstream=proxy(127.0.0.1):4443 TLS"
    return result


class DatasetProgress:
    def __init__(self, harness, enabled=False):
        self.harness = harness
        self.enabled = enabled
        self.stage = "prepare"
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.thread = None
        if enabled:
            from src.data_generation.generator import ROOT
            self.roles = json.loads((ROOT / "experiments/lab_roles.json").read_text())["roles"]
            self.thread = threading.Thread(target=self.heartbeat, daemon=True)
            self.thread.start()

    def say(self, message):
        if self.enabled:
            stamp = datetime.now(LOCAL_TZ).strftime("%H:%M:%S +07")
            print(f"[{stamp}] {message}", flush=True)

    def phase(self, stage):
        self.stage = stage
        self.say(stage)

    def case(self, name):
        if not self.enabled:
            return
        from src.data_generation.generator import SCENARIOS
        fixture, label, expected_rule = SCENARIOS[name]
        route = case_endpoints(name, self.roles, self.harness.config.get("collection_profile"))
        self.phase(f"CASE START {name} | {route} | label={label} | crypto_profile={fixture or 'negotiated/default'} | expected_rule={expected_rule or 'behavior/manifest'}")

    def background_routes(self):
        self.say("BACKGROUND | src=client(172.30.10.10) -> dst=proxy(172.30.20.10):443 TLS")
        self.say("BACKGROUND | src=web-frontend(172.30.30.10) -> dst=backend(172.30.30.20):8000 HTTP -> db(172.30.30.30):5432")
        self.say("BACKGROUND | client(172.30.10.10) -> bastion(172.30.20.20):2222 -> web-frontend(172.30.30.10):22 SSH")
        self.say("Endpoints above describe scheduled actions; Zeek may observe NAT aliases.")

    def heartbeat(self):
        # Không log từng request để terminal dễ đọc trong campaign dài.
        while not self.stop.wait(15):
            with self.harness.lock:
                counts = dict(self.harness.background_counts)
                failures = dict(self.harness.background_failures)
            self.say(f"RUNNING elapsed={time.monotonic() - self.started:.0f}s | stage={self.stage} | background_success={counts} | background_failures={failures}")

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
