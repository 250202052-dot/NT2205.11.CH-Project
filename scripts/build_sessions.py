"""Ghép Zeek JSON logs thành CSV, một dòng cho mỗi UID trong conn.log.

Chạy: python scripts/build_sessions.py
Chỉ dùng Python standard library, không cần cài thêm package.
"""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Tên cột CSV bên trái, tên field thực tế của Zeek bên phải.
CONNECTION_FIELDS = {
    "src_ip": "id.orig_h", "src_port": "id.orig_p",
    "dst_ip": "id.resp_h", "dst_port": "id.resp_p",
    "transport_protocol": "proto", "duration_seconds": "duration",
    "src_bytes": "orig_bytes", "dst_bytes": "resp_bytes",
    "src_packets": "orig_pkts", "dst_packets": "resp_pkts",
    "connection_state": "conn_state",
}
TLS_FIELDS = {
    "tls_version": "version", "tls_cipher": "cipher", "tls_curve": "curve",
    "tls_established": "established", "tls_resumed": "resumed",
}
SSH_FIELDS = {
    "ssh_version": "version", "ssh_client": "client", "ssh_server": "server",
    "ssh_kex": "kex_alg", "ssh_cipher": "cipher_alg", "ssh_mac": "mac_alg",
    "ssh_host_key_algorithm": "host_key_alg", "ssh_auth_attempts": "auth_attempts",
}
CERTIFICATE_FIELDS = {
    "cert_key_type": "certificate.key_type",
    "cert_key_bits": "certificate.key_length",
    "cert_signature_algorithm": "certificate.sig_alg",
}
CSV_COLUMNS = [
    "uid", "timestamp_unix", "timestamp_utc", "application_protocol",
    *CONNECTION_FIELDS, *TLS_FIELDS, *SSH_FIELDS,
    *CERTIFICATE_FIELDS, "cert_validity_days",
]


def read_log_index(log_directory, log_type, key_field):
    """Đọc file hiện tại + file đã rotate, tạo bảng tra cứu UID/fingerprint."""
    index = {}
    paths = sorted(log_directory.glob(f"{log_type}*.log"))
    # Đọc tên cơ bản sau snapshots khi chúng chứa record cùng timestamp.
    paths.sort(key=lambda path: path.name == f"{log_type}.log")
    for path in paths:
        with path.open(encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"JSON không hợp lệ: {path.name}, dòng {line_number}. "
                        "Nếu Zeek đang ghi log, đợi một chút rồi chạy lại."
                    ) from error
                if not isinstance(record, dict) or not record.get(key_field):
                    raise ValueError(
                        f"Thiếu {key_field}: {path.name}, dòng {line_number}"
                    )
                key = record[key_field]
                previous = index.get(key)
                # Một UID trong nhiều file vẫn chỉ tạo một dòng CSV.
                if previous is None or record.get("ts", 0) >= previous.get("ts", 0):
                    index[key] = record
    return index


def copy_fields(row, record, mapping):
    """Field không có -> ô CSV trống; số 0 và False được giữ nguyên."""
    for column, field in mapping.items():
        row[column] = record.get(field)


def build_sessions(log_directory, output_path):
    """Ghép logs, ghi CSV snapshot mới và trả về số connection."""
    if not log_directory.is_dir():
        raise ValueError(f"Không tìm thấy thư mục log: {log_directory}")
    connections = read_log_index(log_directory, "conn", "uid")
    if not connections:
        raise ValueError("Chưa có record trong conn*.log. Tạo traffic rồi chạy lại.")
    tls_sessions = read_log_index(log_directory, "ssl", "uid")
    ssh_sessions = read_log_index(log_directory, "ssh", "uid")
    certificates = read_log_index(log_directory, "x509", "fingerprint")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        # UTF-8 BOM giúp Excel đọc CSV UTF-8 trên Windows.
        with temporary_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            ordered = sorted(
                connections.values(), key=lambda item: (item.get("ts", 0), item["uid"])
            )
            for connection in ordered:
                uid = connection["uid"]
                tls = tls_sessions.get(uid, {})
                ssh = ssh_sessions.get(uid, {})
                row = {column: None for column in CSV_COLUMNS}
                row["uid"] = uid
                row["timestamp_unix"] = connection.get("ts")
                if connection.get("ts") is not None:
                    row["timestamp_utc"] = datetime.fromtimestamp(
                        connection["ts"], timezone.utc
                    ).isoformat()
                # Nhận diện bằng log handshake, không đoán chỉ từ port.
                row["application_protocol"] = (
                    "tls" if tls else "ssh" if ssh else connection.get("service")
                )
                copy_fields(row, connection, CONNECTION_FIELDS)
                copy_fields(row, tls, TLS_FIELDS)
                copy_fields(row, ssh, SSH_FIELDS)

                # X.509 không có UID; nối bằng fingerprint đầu tiên của TLS chain.
                chain = tls.get("cert_chain_fps") or []
                certificate = certificates.get(chain[0], {}) if chain else {}
                copy_fields(row, certificate, CERTIFICATE_FIELDS)
                start = certificate.get("certificate.not_valid_before")
                end = certificate.get("certificate.not_valid_after")
                if start is not None and end is not None:
                    # Tổng thời hạn hiệu lực, không phải số ngày còn lại.
                    row["cert_validity_days"] = (end - start) / 86400
                writer.writerow(row)
        # Thay snapshot cũ khi đã ghi xong, tránh CSV dang dở khi có lỗi.
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return len(connections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, default=PROJECT_ROOT / "logs")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data/sessions.csv")
    args = parser.parse_args()
    try:
        count = build_sessions(args.logs, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print(f"OK: {count} sessions -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
