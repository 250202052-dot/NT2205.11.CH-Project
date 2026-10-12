"""Metadata-only behavior evidence, independent of scenario labels."""
from bisect import bisect_left, bisect_right
from collections import defaultdict


def evaluate(sessions, resolve_roles, configuration, window_seconds=10, burst_threshold=6):
    groups = defaultdict(list)
    for row in sessions:
        if row.get("application_protocol") == "ssh":
            groups[(row["src_ip"], row["dst_ip"], row["dst_port"])].append(float(row["timestamp_unix"]))
    for times in groups.values():
        times.sort()
    baseline = {tuple(map(str, path)) for path in configuration["baseline_ssh_paths"]}
    result = {}
    for row in sessions:
        evidence = {"rules": set(), "ssh_connections_10s": None}
        if row.get("application_protocol") == "ssh":
            ts = float(row["timestamp_unix"])
            times = groups[(row["src_ip"], row["dst_ip"], row["dst_port"])]
            count = bisect_right(times, ts) - bisect_left(times, ts - window_seconds)
            evidence["ssh_connections_10s"] = count
            if count >= burst_threshold:
                evidence["rules"].add("SSH_CONNECTION_BURST")
            src, dst = resolve_roles(row, configuration)
            if (str(row["dst_port"]) == "22" and src != "unknown" and dst != "unknown"
                    and (src, dst, str(row["dst_port"])) not in baseline):
                evidence["rules"].add("SSH_NEW_PATH")
        result[row["uid"]] = evidence
    return result
