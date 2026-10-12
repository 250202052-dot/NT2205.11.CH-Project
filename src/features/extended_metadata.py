"""Ghép log mới bằng UID, xuất bảng bổ sung; giữ nguyên schema baseline.

metadata_extensions.csv là companion của labeled_sessions.csv. Khóa join:
(run_id, uid). Nếu sensor chưa thu field thì để trống, không tạo số giả.
"""

import csv
import json
from pathlib import Path

from data.schemas.validate_extended_metadata import PACKET_FIELDS, TLS_FIELDS, validate_record
from src.features.build_sessions import read_log_index
from src.features.label_sessions import checksum

VERSION = "session-extensions-v1"
COLUMNS = ["run_id", "uid", "extension_version", "packet_metadata_present", "tls_extensions_present",
           "packet_ts", "tls_extensions_ts", "packet_metadata_version", "tls_extensions_version"] + PACKET_FIELDS + TLS_FIELDS
ARRAYS = {"pkt_size_vector", "pkt_direction_vector", "tcp_flags_orig", "tcp_flags_resp",
          "client_extensions", "server_extensions", "client_signature_schemes"}
BOOLS = {"packet_metadata_present", "tls_extensions_present", "sequence_truncated",
         "client_hello_observed", "server_hello_observed", "ech_observed"}
FLOATS = {"packet_ts", "tls_extensions_ts", "orig_iat_mean", "orig_iat_std", "resp_iat_mean", "resp_iat_std"}
STRINGS = {"run_id", "uid", "extension_version", "packet_metadata_version", "tls_extensions_version"}


def schema():
    return {"extension_version": VERSION, "columns": COLUMNS,
            "types": {c: "array[int]" if c in ARRAYS else "bool" if c in BOOLS else "float" if c in FLOATS
                      else "string" if c in STRINGS else "int" for c in COLUMNS},
            "join_key": ["run_id", "uid"], "iat_unit": "seconds", "std_definition": "population",
            "packet_size_definition": "IP total length, excludes Ethernet/VXLAN overhead",
            "flag_order": ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]}


def raw_indices(logs):
    """Log cũ không có stream mới -> index rỗng, vẫn đọc được dataset cũ."""
    indices = {stream: read_log_index(logs, stream, "uid") for stream in ("packet_metadata", "tls_extensions")}
    # Tái sử dụng allowlist validator trước khi dùng raw log.
    if any(indices.values()):
        from data.schemas.validate_zeek_metadata import validate
        validate(logs)
    return indices


def companion_rows(baseline, indices):
    result = []
    for base in baseline:
        row = dict.fromkeys(COLUMNS)
        row.update(run_id=base["run_id"], uid=base["uid"], extension_version=VERSION)
        for stream, fields, present, ts_field, version_field in (
            ("packet_metadata", PACKET_FIELDS, "packet_metadata_present", "packet_ts", "packet_metadata_version"),
            ("tls_extensions", TLS_FIELDS, "tls_extensions_present", "tls_extensions_ts", "tls_extensions_version")):
            record = indices[stream].get(base["uid"])
            row[present] = record is not None
            if record:
                validate_record(stream, record)
                row[ts_field], row[version_field] = record["ts"], record["metadata_version"]
                row.update({field: record.get(field) for field in fields})
        result.append(row)
    return result


def decode(value, kind):
    """CSV chuỗi -> kiểu chuẩn trước validation và export Parquet."""
    if value is None or value == "":
        return None
    if kind == "array[int]":
        return value if isinstance(value, list) else json.loads(value)
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if str(value).lower() not in {"true", "false"}:
            raise ValueError("Invalid companion boolean")
        return str(value).lower() == "true"
    if kind == "float":
        return float(value)
    if kind == "int":
        # Không chấp nhận 1.5 rồi cắt về 1.
        if str(value).strip() != str(int(value)):
            raise ValueError("Invalid companion integer")
        return int(value)
    return str(value)


def validate_rows(rows):
    seen = set()
    types = schema()["types"]
    for raw in rows:
        if set(raw) != set(COLUMNS):
            raise ValueError("Companion field allowlist mismatch")
        row = {key: decode(value, types[key]) for key, value in raw.items()}
        key = row["run_id"], row["uid"]
        if not all(key) or key in seen or row["extension_version"] != VERSION:
            raise ValueError("Invalid companion provenance/duplicate")
        seen.add(key)
        for identifier in key:
            if len(identifier) > 200 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in identifier):
                raise ValueError("Invalid companion ID token")
        for stream, fields, present, ts_field, version_field in (
            ("packet_metadata", PACKET_FIELDS, "packet_metadata_present", "packet_ts", "packet_metadata_version"),
            ("tls_extensions", TLS_FIELDS, "tls_extensions_present", "tls_extensions_ts", "tls_extensions_version")):
            if type(row[present]) is not bool:
                raise ValueError("Missing companion presence flag")
            if row[present]:
                record = {f: row[f] for f in fields if row[f] is not None}
                record.update(uid=row["uid"], ts=row[ts_field], metadata_version=row[version_field])
                validate_record(stream, record)
            elif any(row[f] is not None for f in fields + [ts_field, version_field]):
                raise ValueError("Absent metadata must not contain fabricated values")
    return {"passed": True, "rows": len(rows), "extension_version": VERSION}


def write_companion(output, rows, parquet=False):
    """Output là thư mục extended/, không thêm CSV vào thư mục baseline."""
    output.mkdir(parents=True, exist_ok=True)
    validate_rows(rows)
    with (output / "metadata_extensions.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows({key: json.dumps(value) if isinstance(value, list) else value for key, value in row.items()} for row in rows)
    (output / "schema.json").write_text(json.dumps(schema(), indent=2), encoding="utf-8")
    if parquet:
        import pyarrow as pa
        import pyarrow.parquet as pq
        type_map = {"array[int]": pa.list_(pa.int64()), "bool": pa.bool_(), "float": pa.float64(), "int": pa.int64(), "string": pa.string()}
        arrow_schema = pa.schema([(c, type_map[schema()["types"][c]]) for c in COLUMNS])
        pq.write_table(pa.Table.from_pylist(rows, schema=arrow_schema), output / "metadata_extensions.parquet")
    report = validate_companion(output)
    report.update(packet_rows=sum(bool(row["packet_metadata_present"]) for row in rows),
                  tls_extension_rows=sum(bool(row["tls_extensions_present"]) for row in rows))
    (output / "privacy_validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    digests = {p.name: checksum(p) for p in output.iterdir() if p.is_file() and p.name != "checksums.json"}
    (output / "checksums.json").write_text(json.dumps(digests, indent=2), encoding="utf-8")
    return report


def validate_companion(directory):
    if json.loads((directory / "schema.json").read_text()) != schema():
        raise ValueError("Companion schema/version mismatch")
    with (directory / "metadata_extensions.csv").open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ValueError("Companion CSV header mismatch")
        rows = list(reader)
    report = validate_rows(rows)
    parquet = directory / "metadata_extensions.parquet"
    if parquet.exists():
        import pyarrow.parquet as pq
        table = pq.read_table(parquet)
        if table.column_names != COLUMNS:
            raise ValueError("Companion Parquet header mismatch")
        typed_rows = table.to_pylist()
        validate_rows(typed_rows)
        expected = [{key: decode(value, schema()["types"][key]) for key, value in row.items()} for row in rows]
        if typed_rows != expected:
            raise ValueError("Companion CSV/Parquet contents differ")
    return report


def export_run(directory, parquet=False):
    from data.schemas.validate_zeek_metadata import validate_dataset
    status = json.loads((directory / "run_status.json").read_text(encoding="utf-8"))
    if not status.get("completed") or not status.get("cleanup_passed"):
        raise ValueError("Export only a completed and cleaned-up custom round")
    validate_dataset(directory)
    with (directory / "labeled_sessions.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = write_companion(directory / "extended", companion_rows(rows, raw_indices(directory / "zeek")), parquet)
    # Companion có manifest checksum riêng; không sửa checksum/source dataset cũ.
    return result
