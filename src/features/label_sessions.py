"""Join validated Zeek sessions to scenario ground truth, never to rule-derived labels."""
import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import math
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.features.build_sessions import build_sessions, CSV_COLUMNS, iter_log_records
from src.features.behavior_rules import evaluate

LABELS = {"benign", "misconfiguration", "policy_violation", "attack_behavior"}
MANIFEST_REQUIRED = ["scenario_id", "start_time", "end_time", "src_role", "dst_role",
                     "protocol", "expected_rule", "ground_truth_label"]
LABEL_COLUMNS = ["run_id", "scenario_id", "src_role", "dst_role", "ground_truth_label",
                 "feature_version", "label_version", "label_status", "expected_behavior", "expected_rule", "observed_rules",
                 "expected_rule_observed", "notice_count"]
DERIVED_COLUMNS = ["ssh_connections_10s"]
FEATURE_VERSION = "metadata-crypto-v1+sessions-v2"
LABEL_VERSION = "lab-label-v1"


def dataset_types():
    integers = {"src_port", "dst_port", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "missed_bytes",
                "tls_chain_length", "ssh_version", "ssh_auth_attempts", "cert_key_bits", "cert_san_dns_count",
                "cert_san_ip_count", "notice_count", "ssh_connections_10s"}
    floats = {"timestamp_unix", "duration_seconds", "cert_not_valid_before", "cert_not_valid_after",
              "cert_validity_days", "cert_remaining_days_at_session"}
    booleans = {"tls_established", "tls_resumed", "tls_certificate_visible", "tls_hostname_matches",
                "ssh_auth_success_inferred", "expected_rule_observed"}
    return {key: "int" if key in integers else "float" if key in floats else "bool" if key in booleans else "string"
            for key in CSV_COLUMNS + DERIVED_COLUMNS + LABEL_COLUMNS}


def typed_value(value, kind):
    if value is None or value == "":
        return None
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    if kind == "bool":
        if str(value).lower() not in {"true", "false"}:
            raise ValueError("Invalid boolean")
        return str(value).lower() == "true"
    return str(value)


def timestamp(value):
    try:
        result = float(value)
    except (ValueError, TypeError):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Manifest ISO timestamps must include timezone")
        result = parsed.timestamp()
    if not math.isfinite(result):
        raise ValueError("Non-finite timestamp")
    return result


def load_manifest(path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not set(MANIFEST_REQUIRED) <= set(reader.fieldnames or []):
            raise ValueError("Manifest missing required columns")
        rows = list(reader)
    ids = set()
    for row in rows:
        if not row["scenario_id"] or row["scenario_id"] in ids:
            raise ValueError("Empty/duplicate scenario_id")
        ids.add(row["scenario_id"])
        row["start"] = timestamp(row["start_time"])
        row["end"] = timestamp(row["end_time"])
        if row["end"] <= row["start"] or row["ground_truth_label"] not in LABELS:
            raise ValueError(f"Invalid window/label: {row['scenario_id']}")
        if row["protocol"] not in {"tls", "ssh", "tcp", "udp"}:
            raise ValueError("Unsupported manifest protocol")
        if row.get("completed", "true").lower() != "true":
            raise ValueError("Refusing incomplete scenario manifest")
    return rows


def resolve_roles(session, configuration):
    index = {ip: role for role, ips in configuration["roles"].items() for ip in ips}
    src, dst = index.get(session.get("src_ip"), "unknown"), index.get(session.get("dst_ip"), "unknown")
    for alias in configuration.get("nat_aliases", []):
        if (alias["side"] == "src" and session.get("src_ip") == alias["ip"]
                and str(session.get("dst_port")) == str(alias["dst_port"])
                and dst in alias["dst_roles"]):
            src = alias["role"]
    return src, dst


def endpoint_matches(session, window, roles):
    if roles != (window["src_role"], window["dst_role"]):
        return False
    proto = session.get("application_protocol")
    if window["protocol"] in {"tcp", "udp"}:
        proto = session.get("transport_protocol")
    # Handshake-free/incomplete sessions can match an explicit controlled SSH/TLS
    # selector, but are flagged missing protocol evidence in the output.
    if proto != window["protocol"]:
        if not (not proto and window.get("dst_port") and window["protocol"] in {"tls", "ssh"}):
            return False
    for field in ("src_ip", "dst_ip", "src_port", "dst_port"):
        if window.get(field) and str(session.get(field)) != window[field]:
            return False
    if window.get("session_uids") and session["uid"] not in window["session_uids"].split(";"):
        return False
    return True


def assign_label(session, windows, configuration):
    roles = resolve_roles(session, configuration)
    start = timestamp(session["timestamp_unix"])
    duration = float(session.get("duration_seconds") or 0)
    if not math.isfinite(duration) or duration < 0:
        return None, "invalid_duration", roles
    end = start + duration
    candidates, boundary = [], False
    for window in windows:
        if not endpoint_matches(session, window, roles):
            continue
        if window["start"] <= start < window["end"] and end <= window["end"]:
            candidates.append(window)
        elif start < window["end"] and end > window["start"]:
            boundary = True
    if len(candidates) > 1:
        return None, "ambiguous_manifest", roles
    if boundary:
        return None, "boundary_overlap", roles
    if not candidates:
        return None, "unmatched", roles
    status = "matched" if session.get("application_protocol") else "matched_missing_protocol_metadata"
    return candidates[0], status, roles


def read_notice_evidence(logs):
    result = {}
    # Notice is 1-n by UID. Deduplicate rotated/snapshot copies without dropping
    # different rules or later events for the same connection.
    seen = set()
    for record in iter_log_records(logs, "notice"):
        identity = json.dumps(record, sort_keys=True)
        if identity in seen or not record.get("uid"):
            continue
        seen.add(identity)
        evidence = result.setdefault(record["uid"], {"rules": set(), "count": 0})
        evidence["count"] += 1
        if record.get("rule_id"):
            evidence["rules"].add(record["rule_id"])
    return result


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_tables(output, accepted, rejected, parquet=False):
    columns = CSV_COLUMNS + DERIVED_COLUMNS + LABEL_COLUMNS
    for name, rows in (("labeled_sessions.csv", accepted), ("quarantined_sessions.csv", rejected)):
        with (output / name).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    if parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        for name, rows in (("labeled_sessions", accepted), ("quarantined_sessions", rejected)):
            types = dataset_types()
            arrow_types = {"string": pa.string(), "int": pa.int64(), "float": pa.float64(), "bool": pa.bool_()}
            table = pa.Table.from_pylist([{key: typed_value(row[key], types[key]) for key in columns} for row in rows],
                                         schema=pa.schema([(key, arrow_types[types[key]]) for key in columns]))
            pq.write_table(table, output / f"{name}.parquet")


def write_schema(output):
    columns = CSV_COLUMNS + DERIVED_COLUMNS + LABEL_COLUMNS
    (output / "schema.json").write_text(json.dumps({"columns": columns, "types": dataset_types(), "labels": sorted(LABELS),
        "feature_version": FEATURE_VERSION, "label_version": LABEL_VERSION,
        "missing_values": "CSV: blank; Parquet: null. Set/vector features are JSON strings.",
        "exclude_from_model_inputs": LABEL_COLUMNS + ["uid", "timestamp_utc", "timestamp_unix", "src_ip",
        "dst_ip", "tls_policy_version", "tls_policy_violations", "ssh_policy_version", "ssh_policy_violations"],
        "split_policy": "Group by run/scenario/host/time; do not random-split correlated sessions."}, indent=2), encoding="utf-8")


def label_dataset(logs, manifest, roles_path, output, run_id="offline", parquet=False):
    windows = load_manifest(manifest)
    roles_config = json.loads(roles_path.read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    sessions = output / "sessions.csv"
    # build_sessions already runs validate_zeek_metadata.py. Reuse both rather
    # than duplicating feature extraction or the privacy allowlist.
    build_sessions(logs, sessions)
    notices = read_notice_evidence(logs)
    columns = CSV_COLUMNS + DERIVED_COLUMNS + LABEL_COLUMNS
    accepted, rejected = [], []
    with sessions.open(encoding="utf-8-sig", newline="") as handle:
        session_rows = list(csv.DictReader(handle))
    behavior = evaluate(session_rows, resolve_roles, roles_config)
    for session in session_rows:
        window, status, roles = assign_label(session, windows, roles_config)
        evidence = notices.get(session["uid"], {"rules": set(), "count": 0})
        observed = set(evidence["rules"])
        observed.update(behavior[session["uid"]]["rules"])
        for field in ("tls_policy_violations", "ssh_policy_violations"):
            observed.update(json.loads(session.get(field) or "[]"))
        expected = set(filter(None, window["expected_rule"].split(";"))) if window else set()
        row = dict(session, run_id=run_id, scenario_id=window["scenario_id"] if window else "",
                   src_role=roles[0], dst_role=roles[1],
                   ground_truth_label=window["ground_truth_label"] if window else "",
                   feature_version=FEATURE_VERSION, label_version=LABEL_VERSION, label_status=status,
                   expected_behavior=window.get("expected_behavior", "") if window else "",
                   expected_rule=window["expected_rule"] if window else "",
                   observed_rules=json.dumps(sorted(observed)),
                   expected_rule_observed=str(expected <= observed).lower() if expected else "",
                   notice_count=evidence["count"])
        row["ssh_connections_10s"] = behavior[session["uid"]]["ssh_connections_10s"]
        (accepted if window else rejected).append(row)
    write_tables(output, accepted, rejected, parquet)
    counts = Counter(row["ground_truth_label"] for row in accepted)
    per_scenario = Counter(row["scenario_id"] for row in accepted)
    summary = {"feature_version": FEATURE_VERSION, "label_version": LABEL_VERSION,
               "run_id": run_id, "labeled_count": len(accepted), "quarantined_count": len(rejected),
               "label_counts": dict(counts), "scenario_counts": dict(per_scenario),
               "quarantine_reasons": dict(Counter(row["label_status"] for row in rejected)),
               "privacy_validator": "pending final dataset validation",
               "manifest_sha256": checksum(manifest), "roles_sha256": checksum(roles_path),
               "checksums": {},
               "missing_scenarios": [w["scenario_id"] for w in windows if not per_scenario[w["scenario_id"]]]}
    write_schema(output)
    # Reuse the project validator on both raw metadata and every final export.
    import importlib.util
    spec = importlib.util.spec_from_file_location("final_metadata_validator", ROOT / "data/schemas/validate_zeek_metadata.py")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    privacy = validator.validate_dataset(output)
    (output / "privacy_validation.json").write_text(json.dumps(privacy, indent=2), encoding="utf-8")
    summary["privacy_validator"] = "passed raw Zeek and final CSV/Parquet"
    # Bảng bổ sung riêng: không đổi schema/version của baseline đang thu.
    from src.features.extended_metadata import raw_indices, companion_rows, write_companion
    indices = raw_indices(logs)
    if any(indices.values()):
        summary["extended_metadata"] = write_companion(output / "extended", companion_rows(accepted, indices), parquet)
    summary["checksums"] = {p.name: checksum(p) for p in output.iterdir()
                            if p.suffix in {".csv", ".parquet"} or p.name in {"schema.json", "privacy_validation.json"}}
    (output / "dataset_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--roles", type=Path, default=ROOT / "experiments/lab_roles.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default="offline")
    parser.add_argument("--parquet", action="store_true")
    args = parser.parse_args()
    if args.parquet:
        try:
            import pyarrow
        except ImportError:
            parser.error("--parquet needs pyarrow; CSV requires no extra package")
    try:
        summary = label_dataset(args.logs, args.manifest, args.roles, args.output, args.run_id, args.parquet)
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
