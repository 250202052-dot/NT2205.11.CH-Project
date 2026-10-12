"""
Validate emitted JSON field allowlist and final dataset schema.

Mục đích:
- Đảm bảo metadata Zeek chỉ chứa các field được cho phép.
- Kiểm tra format của một số field nhạy cảm như SSH banner, SHA256.
- Kiểm tra dataset CSV/Parquet cuối cùng đúng schema/version của project.
- Ngăn raw payload, private key, TLS secret hoặc dữ liệu ngoài allowlist lọt vào dataset.

Lưu ý:
- Script chỉ kiểm tra cấu trúc/metadata.
- Không in giá trị record ra console.

Bản đồ hàm/khối kiểm tra -> file đầu vào:
- main(): chọn --logs hoặc --dataset, không tự thu hay sửa dữ liệu.
- validate(--logs): đọc các *.log trực tiếp trong thư mục được chọn,
  gồm conn.log, ssl.log, x509.log, ssh.log, notice.log, weird.log.
  Khi bật extended profile: thêm packet_metadata.log và tls_extensions.log;
  khối validate_record kiểm tra bool/numeric/vector, không chấp nhận raw text.
  Mỗi log dùng allowlist riêng trong zeek_metadata_allowlist.json.
  Log khác ngoài allowlist sẽ bị từ chối, không tự bỏ qua.
- Khối SSH banner trong validate(): chỉ kiểm tra ssh.log,
  field client/server (phiên bản giao thức/phần mềm SSH).
- Khối SHA256 trong validate(): kiểm tra khi field xuất hiện;
  ssl.log: cert_spki_sha256, issuer_name_sha256;
  x509.log: spki_sha256, issuer_name_sha256, subject_name_sha256.
  Không áp quy tắc 64 ký tự hex cho mọi fingerprint/JA3/JA4/HASSH.
- Khối đếm record trong validate(): tính trên toàn bộ log đã đọc;
  không bắt buộc mỗi log đều có record (weird.log có thể rỗng).
- validate_dataset(--dataset): đọc schema.json và CSV/Parquet trực tiếp
  trong thư mục dataset; không đọc log Zeek và không duyệt thư mục con.
  sessions.csv/.parquet: feature session trước gán nhãn;
  labeled_sessions.csv/.parquet: feature + nhãn + provenance;
  quarantined_sessions.csv/.parquet: session chưa gán nhãn chắc chắn.
  Các cột ssh_* trong bảng được kiểm tra bằng quy tắc SSH riêng;
  các cột còn lại dùng schema/kiểu/token của dataset.
  labeled_sessions.csv phải có ít nhất một record.

Script này không join conn/ssl/x509/ssh/notice, không gán nhãn scenario
và không kiểm tra checksum. Những bước đó nằm ở các module pipeline khác.
Bảng companion extended/ dùng scripts/dataset_tools.py extended --validate;
validate_dataset() không tự duyệt bảng companion trong thư mục con.
"""

import argparse
import json
from collections import Counter
from pathlib import Path
import re
import csv
import ipaddress
import math
import sys


# File JSON định nghĩa allowlist các stream và field Zeek được phép xuất.
# File này nằm cùng thư mục với script hiện tại.
SCHEMA_PATH = Path(__file__).with_name("zeek_metadata_allowlist.json")

# Thư mục mặc định chứa Zeek metadata logs.
# Vị trí thực tế: <project>/data/lab_metadata/zeek/.
# Có thể đổi sang log của một round bằng --logs <round_directory>/zeek.
DEFAULT_LOGS = Path(__file__).resolve().parents[1] / "lab_metadata/zeek"


def validate(directory):
    """
    Validate các file Zeek metadata dạng JSON-lines.

    Mỗi dòng trong *.log phải:
    - Là một JSON object.
    - Thuộc stream được khai báo trong allowlist.
    - Chỉ chứa field được phép.
    - Không chứa SSH banner/raw value bất hợp lệ.
    - Các hash SHA256 phải đúng format.

    Parameters
    ----------
    directory : Path
        Thư mục chứa các file *.log.

    Returns
    -------
    Counter
        Số record hợp lệ theo từng stream.

    Raises
    ------
    ValueError
        Khi phát hiện stream, field hoặc value không hợp lệ.
    """

    # Đọc schema allowlist.
    schema = json.loads(
        SCHEMA_PATH.read_text(encoding="utf-8")
    )

    # allowed có dạng ví dụ:
    #
    # {
    #     "conn": ["ts", "id.orig_h", ...],
    #     "ssl": [...],
    #     "x509": [...],
    #     "ssh": [...]
    # }
    allowed = schema["streams"]

    # Đếm số record hợp lệ theo stream.
    counts = Counter()

    # Duyệt tất cả file *.log theo thứ tự tên.
    for path in sorted(directory.glob("*.log")):

        # Lấy tên stream từ tên file.
        #
        # Ví dụ:
        # ssh.log  -> ssh
        # ssl.log  -> ssl (metadata TLS, tên log native của Zeek là ssl)
        # conn.log -> conn
        stream = path.name.split(".")[0]

        # Reject stream không có trong allowlist.
        if stream not in allowed:
            raise ValueError(
                f"Disallowed stream: {path.name}"
            )

        # Zeek metadata ở đây được lưu dạng JSON Lines:
        # mỗi dòng là một JSON object độc lập.
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            1,
        ):

            # Bỏ qua dòng trống.
            if not line.strip():
                continue

            # Parse dòng thành JSON.
            record = json.loads(line)

            # Record bắt buộc phải là JSON object/dictionary.
            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected JSON object: {path.name}:{number}"
                )

            # Tìm các field xuất hiện trong record
            # nhưng không nằm trong allowlist của stream.
            extra = set(record) - set(allowed[stream])

            if extra:
                raise ValueError(
                    f"Disallowed fields: "
                    f"{path.name}:{number}: {sorted(extra)}"
                )

            if stream in {"packet_metadata", "tls_extensions"}:
                # Hai log mới chỉ chứa số, bool và vector số, không raw L7.
                root = Path(__file__).resolve().parents[2]
                if str(root) not in sys.path:
                    sys.path.insert(0, str(root))
                from data.schemas.validate_extended_metadata import validate_record
                validate_record(stream, record)

            # ---------------------------------------------------------
            # Validate SSH metadata
            # Đầu vào: ssh.log -> client/server; không xử lý log khác ở khối này.
            # ---------------------------------------------------------
            if stream == "ssh":

                # Kiểm tra cả SSH client banner và server banner.
                for field in ("client", "server"):
                    value = record.get(field)

                    # Cho phép:
                    # - None
                    # - sentinel "unparsed_ssh_banner"
                    # - SSH banner đã được lọc và đúng format
                    #
                    # Ví dụ hợp lệ:
                    # SSH-2.0-OpenSSH_9.6
                    if (
                        value is not None
                        and value != "unparsed_ssh_banner"
                        and not re.fullmatch(
                            r"SSH-[0-9.]+-[A-Za-z0-9_.+@-]{1,128}",
                            value,
                        )
                    ):
                        raise ValueError(
                            f"Unfiltered SSH banner: "
                            f"{path.name}:{number}:{field}"
                        )

            # ---------------------------------------------------------
            # Validate SHA256 fields
            # Đầu vào theo allowlist hiện tại:
            # ssl.log -> cert_spki_sha256, issuer_name_sha256.
            # x509.log -> spki_sha256, issuer_name_sha256, subject_name_sha256.
            # Khối này chỉ kiểm tra field có mặt, không yêu cầu field phải tồn tại.
            # ---------------------------------------------------------
            #
            # Những field này chỉ được lưu dưới dạng hash SHA256 hex.
            #
            # SHA256 hex chuẩn:
            # - 64 ký tự
            # - chỉ 0-9 và a-f
            for field in (
                "spki_sha256",
                "cert_spki_sha256",
                "issuer_name_sha256",
                "subject_name_sha256",
            ):
                if (
                    field in record
                    and not re.fullmatch(
                        r"[0-9a-f]{64}",
                        record[field],
                    )
                ):
                    raise ValueError(
                        f"Invalid SHA256: "
                        f"{path.name}:{number}:{field}"
                    )

            # Record hợp lệ -> tăng counter.
            counts[stream] += 1

    # Tính tổng tất cả stream, không yêu cầu cả sáu log đều có record.
    # Ví dụ weird.log rỗng vẫn hợp lệ nếu conn.log có record hợp lệ.
    # Nếu không đọc được record nào thì coi là validation failed.
    if not counts:
        raise ValueError("No records to validate")

    return counts


def main():
    """
    CLI entry point.

    Script có 2 chế độ:

    1. Validate Zeek metadata:
       python data/schemas/validate_zeek_metadata.py --logs <directory>

    2. Validate final dataset:
       python data/schemas/validate_zeek_metadata.py --dataset <directory>
    """

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    # Directory chứa các Zeek *.log.
    parser.add_argument(
        "--logs",
        type=Path,
        default=DEFAULT_LOGS,
    )

    # Nếu truyền --dataset thì sẽ validate
    # dataset CSV/Parquet cuối cùng thay vì Zeek logs.
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Validate final CSV/Parquet and schema.json",
    )

    args = parser.parse_args()

    try:

        # Nếu user truyền --dataset:
        # validate final dataset.
        if args.dataset:
            result = validate_dataset(args.dataset)

            print(
                "PASS final dataset:",
                json.dumps(result),
            )
            return

        # Nếu không có --dataset:
        # validate Zeek metadata logs.
        counts = validate(args.logs)

    except (OSError, ValueError) as error:

        # Nếu validation fail:
        # exit code = 1.
        parser.exit(
            1,
            f"FAIL: {error}\n",
        )

    # Validation thành công.
    print(
        "PASS metadata allowlist:",
        dict(sorted(counts.items())),
    )


def validate_dataset(directory):
    """
    Validate final CSV/Parquet dataset.

    Đầu vào: schema.json + sessions/labeled_sessions/quarantined_sessions
    dạng CSV/Parquet ngay trong directory. Không đọc conn.log/ssl.log/...
    ở đây; dữ liệu đã được build_sessions/label_sessions xử lý trước đó.
    Không tự duyệt full_collection/, context/ hay splits/; pipeline tổng hợp
    gọi validator riêng cho mỗi thư mục có dữ liệu.

    Quan trọng:
    Schema không được lấy từ file dataset do user cung cấp.

    Script import trực tiếp schema chuẩn từ source code project:
    - CSV_COLUMNS
    - DERIVED_COLUMNS
    - LABEL_COLUMNS
    - dataset_types()

    Việc này tránh trường hợp attacker/user sửa schema.json
    để hợp thức hóa field không được phép.

    Validation bao gồm:
    - Column allowlist.
    - Column order.
    - Data types.
    - Feature version.
    - Label version.
    - IP address format.
    - Policy rule token format.
    - SSH metadata format.
    - Timestamp timezone.
    - Forbidden secret markers.
    - Ground-truth labels.
    - Dataset provenance.
    """

    # v2 training is a separate, code-owned allowlist (no raw host IPs).
    # The baseline schema/version below remains compatible with old captures.
    candidate_schema = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    if candidate_schema.get("schema_version") == "lab-training-v2":
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from src.features.training_dataset import validate_training_dataset
        return validate_training_dataset(directory)

    # Lấy project root.
    root = Path(__file__).resolve().parents[2]

    # Cho phép import các module src.* của project.
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    # Schema gốc của session dataset.
    from src.features.build_sessions import CSV_COLUMNS

    # Các column/type/version được project định nghĩa.
    from src.features.label_sessions import (
        DERIVED_COLUMNS,
        LABEL_COLUMNS,
        LABELS,
        FEATURE_VERSION,
        LABEL_VERSION,
        dataset_types,
        typed_value,
    )

    # Dataset labeled cuối cùng phải gồm:
    #
    # base features
    # + derived features
    # + label/provenance fields
    expected = (
        CSV_COLUMNS
        + DERIVED_COLUMNS
        + LABEL_COLUMNS
    )

    # Đọc schema.json nằm trong dataset directory.
    schema = json.loads(
        (directory / "schema.json").read_text(
            encoding="utf-8"
        )
    )

    # Lấy type definition chuẩn từ code của project.
    types = dataset_types()

    # ---------------------------------------------------------
    # Verify schema
    # ---------------------------------------------------------
    #
    # schema.json phải khớp hoàn toàn:
    # - column list
    # - type definition
    # - feature version
    # - label version
    if (
        schema.get("columns") != expected
        or schema.get("types") != types
        or schema.get("feature_version") != FEATURE_VERSION
        or schema.get("label_version") != LABEL_VERSION
    ):
        raise ValueError(
            "Final schema does not match "
            "project allowlist/version"
        )

    counts = {}

    # ---------------------------------------------------------
    # Validate từng dataset file
    # ---------------------------------------------------------
    for path in sorted(directory.iterdir()):

        # Chỉ validate CSV và Parquet.
        if path.suffix not in {".csv", ".parquet"}:
            continue

        # Dataset chỉ được phép có 3 loại.
        if path.stem not in {
            "sessions",
            "labeled_sessions",
            "quarantined_sessions",
        }:
            raise ValueError(
                f"Unexpected dataset file: {path.name}"
            )

        # sessions chỉ có raw feature columns.
        #
        # labeled_sessions / quarantined_sessions
        # có thêm derived + label/provenance.
        columns = (
            CSV_COLUMNS
            if path.stem == "sessions"
            else expected
        )

        # -----------------------------------------------------
        # Load CSV
        # -----------------------------------------------------
        if path.suffix == ".csv":

            with path.open(
                encoding="utf-8-sig",
                newline="",
            ) as handle:

                reader = csv.DictReader(handle)

                # Field order và field names phải match chính xác.
                if reader.fieldnames != columns:
                    raise ValueError(
                        f"Final field allowlist violation: "
                        f"{path.name}"
                    )

                rows = list(reader)

        # -----------------------------------------------------
        # Load Parquet
        # -----------------------------------------------------
        else:

            import pyarrow.parquet as pq

            table = pq.read_table(path)

            # Kiểm tra schema/column order.
            if table.column_names != columns:
                raise ValueError(
                    f"Final field allowlist violation: "
                    f"{path.name}"
                )

            rows = table.to_pylist()

        # -----------------------------------------------------
        # Validate từng row
        # -----------------------------------------------------
        for number, row in enumerate(rows, 1):

            # csv.DictReader sẽ tạo key None nếu một dòng
            # có nhiều value hơn số column.
            #
            # Đây là dấu hiệu malformed CSV.
            if None in row:
                raise ValueError(
                    f"Extra CSV values: "
                    f"{path.name}:{number}"
                )

            # Kiểm tra từng field.
            for field, value in row.items():

                # Cho phép empty/null.
                if value is None or value == "":
                    continue

                # Lấy expected data type.
                kind = types[field]

                # Convert value sang kiểu chuẩn của project.
                converted = typed_value(
                    value,
                    kind,
                )

                # -------------------------------------------------
                # Numeric validation
                # -------------------------------------------------
                if kind in {"int", "float"}:

                    # Reject NaN / +inf / -inf.
                    if not math.isfinite(converted):
                        raise ValueError(
                            f"Non-finite feature: "
                            f"{path.name}:{number}:{field}"
                        )

                    continue

                # Bool đã được typed_value validate.
                if kind == "bool":
                    continue

                # Các field còn lại xử lý dạng text.
                text = str(value)

                # -------------------------------------------------
                # IP address validation
                # -------------------------------------------------
                if field in {"src_ip", "dst_ip"}:

                    # Support cả IPv4 và IPv6.
                    ipaddress.ip_address(text)

                # -------------------------------------------------
                # Policy violation fields
                # -------------------------------------------------
                elif field in {
                    "tls_policy_violations",
                    "ssh_policy_violations",
                    "observed_rules",
                }:

                    # Field lưu JSON array.
                    values = json.loads(text)

                    # Ví dụ hợp lệ:
                    #
                    # [
                    #   "TLS_WEAK_VERSION",
                    #   "SSH_LEGACY_KEX"
                    # ]
                    #
                    # Token phải:
                    # - là string
                    # - bắt đầu bằng A-Z
                    # - chỉ chứa A-Z, 0-9, _
                    # - tối đa 100 ký tự
                    if (
                        not isinstance(values, list)
                        or not all(
                            isinstance(v, str)
                            and re.fullmatch(
                                r"[A-Z][A-Z0-9_]{0,99}",
                                v,
                            )
                            for v in values
                        )
                    ):
                        raise ValueError(
                            f"Invalid rule tokens: "
                            f"{path.name}:{number}:{field}"
                        )

                # -------------------------------------------------
                # SSH client/server banner
                # -------------------------------------------------
                elif field in {
                    "ssh_client",
                    "ssh_server",
                }:

                    if (
                        text != "unparsed_ssh_banner"
                        and not re.fullmatch(
                            r"SSH-[0-9.]+-"
                            r"[A-Za-z0-9_.+@-]{1,128}",
                            text,
                        )
                    ):
                        raise ValueError(
                            f"Raw SSH banner/content: "
                            f"{path.name}:{number}:{field}"
                        )

                # -------------------------------------------------
                # SSH public key fingerprint
                # -------------------------------------------------
                elif field == "ssh_host_key_fingerprint":

                    # Expected format:
                    # SHA256:<base64>
                    if not re.fullmatch(
                        r"SHA256:[A-Za-z0-9+/=]{20,100}",
                        text,
                    ):
                        raise ValueError(
                            f"Invalid SSH public-key fingerprint: "
                            f"{path.name}:{number}"
                        )

                # -------------------------------------------------
                # Timestamp validation
                # -------------------------------------------------
                elif field == "timestamp_utc":

                    from datetime import datetime

                    # Timestamp phải chứa timezone.
                    #
                    # Ví dụ:
                    # 2026-10-08T12:30:15+00:00
                    parsed = datetime.fromisoformat(text)

                    if parsed.tzinfo is None:
                        raise ValueError(
                            "Timestamp missing timezone"
                        )

                # -------------------------------------------------
                # Generic metadata validation
                # -------------------------------------------------
                else:

                    # Chỉ cho phép metadata token đơn giản.
                    #
                    # Mục đích:
                    # tránh raw payload hoặc binary/string lạ
                    # lọt vào final feature dataset.
                    if not re.fullmatch(
                        r"[A-Za-z0-9_.@:+,; -]{1,1024}",
                        text,
                    ):
                        raise ValueError(
                            f"Invalid metadata token: "
                            f"{path.name}:{number}:{field}"
                        )

                # -------------------------------------------------
                # Secret / payload leak detection
                # -------------------------------------------------
                #
                # Reject các marker có thể cho thấy
                # raw/private content đã lọt vào dataset.
                if any(
                    marker in text
                    for marker in (
                        "PRIVATE_PAYLOAD_MARKER",
                        "PRIVATE KEY",
                        "CLIENT_RANDOM",
                        "TRAFFIC_SECRET",
                    )
                ):
                    raise ValueError(
                        f"Forbidden secret/content marker: "
                        f"{path.name}:{number}:{field}"
                    )

            # -----------------------------------------------------
            # Labeled dataset provenance validation
            # -----------------------------------------------------
            if path.stem == "labeled_sessions":

                # Ground-truth dataset phải có:
                # - valid label
                # - scenario_id
                # - feature version
                # - label version
                if (
                    row.get("ground_truth_label") not in LABELS
                    or not row.get("scenario_id")
                    or row.get("feature_version")
                    != FEATURE_VERSION
                    or row.get("label_version")
                    != LABEL_VERSION
                ):
                    raise ValueError(
                        "Missing/invalid labeled dataset provenance"
                    )

            # -----------------------------------------------------
            # Quarantine dataset validation
            # -----------------------------------------------------
            if (
                path.stem == "quarantined_sessions"
                and row.get("ground_truth_label")
            ):
                # Quarantine records không được có ground truth label,
                # vì chúng chưa đủ điều kiện để đưa vào labeled dataset.
                raise ValueError(
                    "Quarantined session must not be labeled"
                )

        # Lưu số row của file.
        counts[path.name] = len(rows)

    # Final pipeline yêu cầu phải có labeled_sessions.csv
    # và file đó phải có ít nhất một record.
    if not counts.get("labeled_sessions.csv"):
        raise ValueError(
            "No final labeled CSV records"
        )

    # Summary trả về sau validation thành công.
    return {
        "passed": True,
        "schema_version": "final-metadata-v1",
        "files": counts,
        "scope": (
            "Column allowlist, types, provenance and token shapes; "
            "no raw L7/secret fields."
        ),
    }


# Chỉ chạy main() khi script được execute trực tiếp.
#
# Không chạy khi file được import như module.
if __name__ == "__main__":
    main()
