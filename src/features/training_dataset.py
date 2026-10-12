"""Export dataset v2: reuse validated sessions/extended metadata, no raw IP.

Keep local Zeek snapshots for reproducible joins; publish ONLY training/.
HMAC key is outside dataset artifacts. History uses prior observed sessions,
never labels, and resets at every run/gap. Models must exclude provenance.
"""
from collections import Counter, defaultdict, deque
import csv
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets

from src.features.label_sessions import dataset_types, typed_value, checksum, LABELS
from src.features.flow_context import enrich_flows, DERIVED_FLOW_FIELDS
from src.features.extended_metadata import schema as extension_schema, validate_companion, decode

# Configuration & Schema
# -----------------------------------------------------------------------------
VERSION = "lab-training-v2"
DROP = {
    "src_ip", "dst_ip", "src_port", "cert_fingerprint", "cert_spki_sha256",
    "cert_issuer_name_sha256", "ssh_host_key_fingerprint", "expected_rule",
    "observed_rules", "expected_rule_observed", "notice_count", "tls_policy_violations",
    "ssh_policy_violations", "tls_policy_version", "ssh_policy_version", "ssh_connections_10s",
}
HISTORY_TYPES = {
    "src_host_token": "string", "dst_host_token": "string", "cert_spki_token": "string",
    "src_port_class": "string", "baseline_fp_prevalence": "float", "new_edge_score": "int",
    "session_rate_5m": "float", "fanout_5m": "int", "certificate_identity_changed": "bool",
    "attack_family": "string", "ground_truth_source": "string",
}
MASK_FIELDS = {
    "tls_ja3", "tls_ja3s", "tls_ja4", "tls_ja4s", "tls_curve", "client_extensions",
    "server_extensions", "client_signature_schemes", "server_signature_scheme", "ech_observed",
}


def schema():
    # Giữ thứ tự thêm cột vì CSV và Parquet phải có cùng thứ tự schema.
    field_types = {}
    for field, field_type in dataset_types().items():
        if field not in DROP:
            field_types[field] = field_type
    for field in DERIVED_FLOW_FIELDS:
        field_types[field] = "float"
    for field, field_type in extension_schema()["types"].items():
        if field not in {"run_id", "uid"}:
            field_types[field] = field_type
    field_types.update(HISTORY_TYPES)

    provenance_fields = {
        "uid", "run_id", "scenario_id", "ground_truth_label", "feature_version", "label_version",
        "label_status", "expected_behavior", "attack_family", "ground_truth_source",
        "timestamp_unix", "timestamp_utc", "src_host_token", "dst_host_token", "cert_spki_token",
        "packet_ts", "tls_extensions_ts", "packet_metadata_version", "tls_extensions_version",
        "extension_version",
    }
    return {
        "schema_version": VERSION, "feature_version": VERSION, "label_version": "lab-label-v1",
        "columns": list(field_types), "types": field_types,
        "exclude_from_model_inputs": sorted(provenance_fields),
        "history_definition": "Prior starts only, reset by run; fp/cert history uses only completed prior sessions. Rate=count/300 seconds.",
        "missing_values": "CSV blank; Parquet null. No fabricated metadata.",
        "raw_l7_retained": False,
        "host_pseudonymization": "HMAC-SHA256 with a private per-project key; pseudonymous, not anonymous",
    }


# CSV Reading & HMAC Pseudonymization
# -----------------------------------------------------------------------------
def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def iter_csv(path):
    # Đọc từng dòng để validator không giữ cả dataset lớn hai lần trong RAM.
    with path.open(encoding="utf-8-sig", newline="") as handle:
        yield from csv.DictReader(handle)


def load_key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        # Exclusive creation prevents replacing an existing project identity.
        try:
            with path.open("xb") as handle:
                handle.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("HMAC key must contain exactly 32 bytes")
    return key


def token(key, namespace, value):
    if not value:
        return None
    message = f"{namespace}:{value}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# Historical Features
# -----------------------------------------------------------------------------
def historical_features(rows):
    """Return by (run_id, uid). Equal timestamps don't see each other.

    Identity/fingerprint becomes observable at connection completion, so a
    long connection cannot teach an earlier-starting session its certificate.
    """
    history_by_session = {}
    rows_by_run = defaultdict(list)
    for row in rows:
        rows_by_run[row["run_id"]].append(row)

    for run_id, run_rows in rows_by_run.items():
        sessions_by_start = sorted(
            run_rows, key=lambda row: (float(row["timestamp_unix"]), row["uid"])
        )
        # Mỗi run có lịch sử riêng; không nối qua thời gian máy ngừng thu.
        recent_starts_by_source = defaultdict(deque)
        observed_edges = set()
        fingerprint_counts = Counter()
        fingerprint_totals = Counter()
        certificates_by_destination = {}
        sessions_by_completion = sorted(
            run_rows,
            key=lambda row: float(row["timestamp_unix"]) + float(row.get("duration_seconds") or 0),
        )
        completion_index = 0
        pending_starts = []
        last_start_time = None

        for row in sessions_by_start:
            start_time = float(row["timestamp_unix"])
            # Chỉ thêm batch cũ khi timestamp đổi: phiên cùng giờ không thấy nhau.
            if start_time != last_start_time:
                for previous_session in pending_starts:
                    previous_source = previous_session["src_ip"]
                    previous_start = float(previous_session["timestamp_unix"])
                    previous_destination = previous_session["dst_ip"]
                    recent_starts_by_source[previous_source].append(
                        (previous_start, previous_destination)
                    )
                    previous_edge = (
                        previous_source, previous_destination,
                        previous_session["application_protocol"], previous_session["dst_port"],
                    )
                    observed_edges.add(previous_edge)
                pending_starts = []
                last_start_time = start_time

            # Fingerprint/cert chỉ vào lịch sử khi phiên kết thúc trước start hiện tại.
            while completion_index < len(sessions_by_completion):
                previous_session = sessions_by_completion[completion_index]
                previous_start = float(previous_session["timestamp_unix"])
                previous_duration = float(previous_session.get("duration_seconds") or 0)
                completion_time = previous_start + previous_duration
                if completion_time >= start_time:
                    break
                completion_index += 1

                previous_protocol = previous_session["application_protocol"]
                if previous_protocol == "tls":
                    previous_fingerprint = previous_session.get("tls_ja4") or previous_session.get("tls_ja3")
                else:
                    previous_fingerprint = previous_session.get("ssh_hassh") or previous_session.get("ssh_ja4ssh")
                if previous_fingerprint:
                    fingerprint_counts[(previous_protocol, previous_fingerprint)] += 1
                    fingerprint_totals[previous_protocol] += 1

                previous_identity = previous_session.get("cert_spki_sha256")
                if previous_identity:
                    destination_key = (previous_session["dst_ip"], previous_session["dst_port"])
                    certificates_by_destination[destination_key] = previous_identity

            source_ip = row["src_ip"]
            protocol = row["application_protocol"]
            recent_starts = recent_starts_by_source[source_ip]
            window_start = start_time - 300
            # Giữ start đúng biên 300 giây; không tính phiên hiện tại vào rate/fanout.
            while recent_starts and recent_starts[0][0] < window_start:
                recent_starts.popleft()

            if protocol == "tls":
                fingerprint = row.get("tls_ja4") or row.get("tls_ja3")
            else:
                fingerprint = row.get("ssh_hassh") or row.get("ssh_ja4ssh")
            fingerprint_prevalence = None
            if fingerprint and fingerprint_totals[protocol]:
                matching_count = fingerprint_counts[(protocol, fingerprint)]
                fingerprint_prevalence = matching_count / fingerprint_totals[protocol]

            certificate_identity = row.get("cert_spki_sha256")
            destination_key = (row["dst_ip"], row["dst_port"])
            previous_certificate = certificates_by_destination.get(destination_key)
            certificate_changed = None
            if certificate_identity and previous_certificate:
                certificate_changed = certificate_identity != previous_certificate

            current_edge = (source_ip, row["dst_ip"], protocol, row["dst_port"])
            recent_destinations = {destination for _, destination in recent_starts}
            history_by_session[(run_id, row["uid"])] = {
                "baseline_fp_prevalence": fingerprint_prevalence,
                "new_edge_score": int(current_edge not in observed_edges),
                "session_rate_5m": len(recent_starts) / 300,
                "fanout_5m": len(recent_destinations),
                "certificate_identity_changed": certificate_changed,
            }
            pending_starts.append(row)
    return history_by_session


# Training Row Construction
# -----------------------------------------------------------------------------
def training_rows(selected, observed, extras, key):
    # Tính lịch sử từ toàn bộ quan sát, không từ subset đã sampling để train.
    history_by_session = historical_features(observed)
    flows_by_session = {}
    for flow_row in enrich_flows(observed):
        session_key = (flow_row["run_id"], flow_row["uid"])
        flows_by_session[session_key] = flow_row

    output_types = schema()["types"]
    base_types = dataset_types()
    extension_types = extension_schema()["types"]
    output_rows = []
    for base_row in selected:
        session_key = (base_row["run_id"], base_row["uid"])
        row = {}
        for field, value in base_row.items():
            if field in base_types and field not in DROP:
                row[field] = typed_value(value, base_types[field])
        for field in DERIVED_FLOW_FIELDS:
            row[field] = flows_by_session[session_key][field]

        extra_metadata = extras.get(session_key, {})
        for field, field_type in extension_types.items():
            if field not in {"run_id", "uid"}:
                row[field] = decode(extra_metadata.get(field), field_type)
        for field in ("packet_metadata_present", "tls_extensions_present"):
            row[field] = bool(row[field])

        source_port = int(base_row.get("src_port") or 0)
        if source_port < 1024:
            source_port_class = "system"
        elif source_port < 49152:
            source_port_class = "registered"
        else:
            source_port_class = "dynamic"

        attack_family = None
        if base_row["ground_truth_label"] == "attack_behavior":
            attack_family = base_row["expected_behavior"]

        row.update(history_by_session[session_key])
        row["src_host_token"] = token(key, "host", base_row["src_ip"])
        row["dst_host_token"] = token(key, "host", base_row["dst_ip"])
        row["cert_spki_token"] = token(key, "spki", base_row.get("cert_spki_sha256"))
        row["src_port_class"] = source_port_class
        row["feature_version"] = VERSION
        row["attack_family"] = attack_family
        row["ground_truth_source"] = "controlled_lab_manifest"
        output_rows.append({field: row.get(field) for field in output_types})
    return output_rows


# Dataset Writing
# -----------------------------------------------------------------------------
def write_export(output, rows, parquet=False):
    output.mkdir(parents=True, exist_ok=True)
    specification = schema()
    with (output / "labeled_sessions.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=specification["columns"])
        writer.writeheader()
        for row in rows:
            csv_row = {}
            for field, value in row.items():
                if isinstance(value, list):
                    csv_row[field] = json.dumps(value)
                else:
                    csv_row[field] = value
            writer.writerow(csv_row)
    if parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        arrow_types = {
            "string": pa.string(), "int": pa.int64(), "float": pa.float64(),
            "bool": pa.bool_(), "array[int]": pa.list_(pa.int64()),
        }
        arrow_fields = []
        for field, field_type in specification["types"].items():
            arrow_fields.append((field, arrow_types[field_type]))
        arrow_schema = pa.schema(arrow_fields)
        table = pa.Table.from_pylist(rows, schema=arrow_schema)
        pq.write_table(table, output / "labeled_sessions.parquet")
    (output / "schema.json").write_text(json.dumps(specification, indent=2), encoding="utf-8")
    # Required public entry point, not a second unconnected validation path.
    from data.schemas.validate_zeek_metadata import validate_dataset
    privacy_report = validate_dataset(output)
    (output / "privacy_validation.json").write_text(json.dumps(privacy_report, indent=2), encoding="utf-8")
    file_checksums = {}
    for path in output.iterdir():
        if path.is_file() and path.name != "checksums.json":
            file_checksums[path.name] = checksum(path)
    (output / "checksums.json").write_text(json.dumps(file_checksums, indent=2), encoding="utf-8")


# Privacy & Format Validation
# -----------------------------------------------------------------------------
def validate_training_dataset(directory):
    specification = schema()
    stored_schema = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    if stored_schema != specification:
        raise ValueError("Training v2 schema does not match code allowlist")
    allowed_tables = {"labeled_sessions.csv", "labeled_sessions.parquet"}
    for path in directory.iterdir():
        if path.suffix in {".csv", ".parquet"} and path.name not in allowed_tables:
            raise ValueError("Unexpected training v2 table")
    with (directory / "labeled_sessions.csv").open(encoding="utf-8-sig", newline="") as handle:
        if csv.DictReader(handle).fieldnames != specification["columns"]:
            raise ValueError("Training v2 column allowlist mismatch")
    seen_sessions = set()
    typed_rows = []
    row_count = 0
    has_parquet = (directory / "labeled_sessions.parquet").exists()
    for raw_row in iter_csv(directory / "labeled_sessions.csv"):
        row_count += 1
        if set(raw_row) != set(specification["columns"]):
            raise ValueError("Malformed training v2 row")
        row = {}
        for field, value in raw_row.items():
            field_type = specification["types"][field]
            row[field] = decode(value, field_type)
        for field, value in row.items():
            if value is None:
                continue
            field_type = specification["types"][field]
            if field_type in {"int", "float"} and not math.isfinite(value):
                raise ValueError("Non-finite training metadata")
            if field_type == "array[int]":
                if not isinstance(value, list) or len(value) > 1024:
                    raise ValueError("Invalid metadata-only integer vector")
                for item in value:
                    # bool là subclass của int, nhưng không được chấp nhận trong vector.
                    if type(item) is not int or not 0 <= item <= 2**32 - 1:
                        raise ValueError("Invalid metadata-only integer vector")
            if field_type == "string":
                valid_token = re.fullmatch(r"[A-Za-z0-9_.@:+,; -]{1,1024}", value)
                secret_markers = ("PRIVATE_PAYLOAD_MARKER", "PRIVATE KEY", "CLIENT_RANDOM", "TRAFFIC_SECRET")
                contains_secret = any(marker in value for marker in secret_markers)
                if not valid_token or contains_secret:
                    raise ValueError("Forbidden content/secret or invalid metadata token")
            if field in {"src_host_token", "dst_host_token", "cert_spki_token"} and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Invalid HMAC token")
            if field in {"ssh_client", "ssh_server"} and value != "unparsed_ssh_banner":
                valid_banner = re.fullmatch(r"SSH-[0-9.]+-[A-Za-z0-9_.+@-]{1,128}", value)
                if not valid_banner:
                    raise ValueError("Unfiltered SSH banner in training v2")

        session_key = (row["run_id"], row["uid"])
        invalid_provenance = (
            not all(session_key)
            or session_key in seen_sessions
            or row["ground_truth_label"] not in LABELS
            or row["feature_version"] != VERSION
            or row["label_version"] != "lab-label-v1"
        )
        if invalid_provenance:
            raise ValueError("Invalid training provenance/duplicate")
        if not row["src_host_token"] or not row["dst_host_token"] or not row["scenario_id"]:
            raise ValueError("Missing training identity/provenance")
        seen_sessions.add(session_key)
        # Chỉ giữ thêm bản typed khi cần đối chiếu Parquet, tránh tốn RAM cho CSV-only.
        if has_parquet:
            typed_rows.append(row)
    if not row_count:
        raise ValueError("No training v2 records")
    if has_parquet:
        import pyarrow.parquet as pq
        table = pq.read_table(directory / "labeled_sessions.parquet")
        matching_columns = table.column_names == specification["columns"]
        if not matching_columns or table.to_pylist() != typed_rows:
            raise ValueError("Training CSV/Parquet mismatch")
    return {"passed": True, "rows": row_count, "feature_version": VERSION, "raw_ip_columns": 0, "raw_l7_columns": 0}


# Main Workflow: Validate → Build Rows → Export → Quality Report
# -----------------------------------------------------------------------------
def export_campaign(source, key_path, parquet=False, simple_output=False):
    from data.schemas.validate_zeek_metadata import validate_dataset

    # 1. Đọc các session đã gắn nhãn và toàn bộ quan sát cho feature lịch sử.
    validate_dataset(source)
    selected = read_csv(source / "labeled_sessions.csv")
    observed_by_session = {}
    for folder in (source / "full_collection", source / "context", source):
        if (folder / "labeled_sessions.csv").exists():
            validate_dataset(folder)
            for row in read_csv(folder / "labeled_sessions.csv"):
                session_key = (row["run_id"], row["uid"])
                observed_by_session[session_key] = row
    # Giữ thứ tự folder: bản ở source thay thế bản cùng session đã đọc trước đó.

    # 2. Đọc metadata bổ sung, rồi dùng khóa HMAC riêng của project.
    extras = {}
    if (source / "extended").exists():
        validate_companion(source / "extended")
        for row in read_csv(source / "extended/metadata_extensions.csv"):
            session_key = (row["run_id"], row["uid"])
            extras[session_key] = row
    observed = list(observed_by_session.values())
    key = load_key(key_path)
    rows = training_rows(selected, observed, extras, key)

    # 3. Xuất dataset chính; các split chỉ chọn lại session, không tính lại history.
    output = source / "training"
    write_export(output, rows, parquet)
    split_names = ()
    if not simple_output:
        split_names = ("train", "validation", "test")
    for split_name in split_names:
        path = source / "splits" / split_name / "labeled_sessions.csv"
        if path.exists():
            split_sessions = {(row["run_id"], row["uid"]) for row in read_csv(path)}
            split_rows = []
            for row in rows:
                session_key = (row["run_id"], row["uid"])
                if session_key in split_sessions:
                    split_rows.append(row)
            write_export(output / "splits" / split_name, split_rows, parquet)

    # 4. Chế độ đầy đủ giữ sample và bài test che feature như trước.
    if not simple_output:
        write_export(output / "sample", rows[:min(100, len(rows))], parquet)
        masked_rows = []
        for row in rows:
            masked_row = {}
            for field, value in row.items():
                if field in MASK_FIELDS:
                    masked_row[field] = None
                else:
                    masked_row[field] = value
            masked_rows.append(masked_row)
        write_export(output / "missing_feature_test", masked_rows, parquet)
        mask_condition = {
            "type": "synthetic_feature_mask", "actual_ech_capture": False,
            "masked_columns": sorted(MASK_FIELDS),
            "note": "Reduced visibility test, not proof of ECH deployment.",
        }
        condition_path = output / "missing_feature_test/condition.json"
        condition_path.write_text(json.dumps(mask_condition, indent=2), encoding="utf-8")

    # 5. Báo cáo chất lượng và checksum cho toàn bộ artifact đã xuất.
    class_counts = Counter(row["ground_truth_label"] for row in rows)
    scenario_counts = Counter(row["expected_behavior"] for row in rows)
    missing_field_counts = {}
    for field in schema()["columns"]:
        missing_field_counts[field] = sum(row[field] is None for row in rows)
    actual_utc_dates = sorted({row["timestamp_utc"][:10] for row in rows})
    report = {
        "feature_version": VERSION, "rows": len(rows), "class_counts": dict(class_counts),
        "scenario_counts": dict(scenario_counts), "missing_field_counts": missing_field_counts,
        "actual_utc_dates": actual_utc_dates, "history_resets_at_run_boundaries": True,
        "key_exported": False,
        "scope": "custom lab only; public sources and holdout experiments remain separate",
    }
    (output / "quality_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    file_checksums = {}
    for path in output.rglob("*"):
        if path.is_file() and path.name != "checksums.json":
            file_checksums[str(path.relative_to(output))] = checksum(path)
    (output / "checksums.json").write_text(json.dumps(file_checksums, indent=2), encoding="utf-8")
    return report
