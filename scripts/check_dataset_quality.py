"""Đánh giá dataset dùng để train; chỉ đọc dữ liệu và in console, không ghi report."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

# Không tạo cả cache .pyc khi chạy công cụ chỉ đọc này.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models.baselines import DATASET_DIRECTORY, get_feature_groups, training_config
from src.models.ablation import load_data
from src.features.label_sessions import assign_label, checksum, load_manifest, resolve_roles
from src.features.training_dataset import iter_csv


def print_overview(splits, labels):
    rows = [row for split_rows in splits.values() for row in split_rows]
    print(f"\n1. SỐ MẪU VÀ NHÃN: {len(rows):,} session")
    for split_name, split_rows in splits.items():
        counts = Counter(row["ground_truth_label"] for row in split_rows)
        run_count = len({row["run_id"] for row in split_rows})
        print(f"  {split_name.upper()}: {len(split_rows):,} mẫu, {run_count} run")
        for label in labels:
            percentage = 100 * counts[label] / len(split_rows)
            print(f"    {label:<20} {counts[label]:>7,} ({percentage:6.2f}%)")

    local_timezone = timezone(timedelta(hours=7))
    local_times = [datetime.fromtimestamp(float(row["timestamp_unix"]), local_timezone) for row in rows]
    dates = sorted({time.date().isoformat() for time in local_times})
    print(f"  Thời gian (+07): {min(local_times).isoformat()} → {max(local_times).isoformat()}")
    print(f"  Ngày thu thực tế: {', '.join(dates)}; block không đồng nghĩa ngày lịch.")
    print("  Tỷ lệ lớp của subset có thể khác dataset thu gốc; đây là mẫu đã chọn để train.")

    print("\n2. SỐ MẪU THEO CASE (expected_behavior), không gộp abnormal thành attack")
    cases = Counter((row["expected_behavior"], row["ground_truth_label"]) for row in rows)
    for (scenario, label), count in sorted(cases.items()):
        print(f"  {scenario:<30} {label:<20} {count:>7,}")
    for earlier, later in (("train", "validation"), ("train", "test")):
        earlier_cases = {row["expected_behavior"] for row in splits[earlier]}
        later_cases = {row["expected_behavior"] for row in splits[later]}
        overlap = earlier_cases & later_cases
        unseen = later_cases - earlier_cases
        print(f"  {later}: {len(overlap)} case đã có trong {earlier}, {len(unseen)} case mới.")
    print("  Cùng case ở split khác không phải trùng session; chưa chứng minh phát hiện attack mới.")
    return rows


def print_feature_quality(rows, splits):
    group = get_feature_groups()["C"]
    fields = group["numeric"] + group["categorical"]
    all_missing = []
    constant_observed = []
    missing_counts = {}
    for field in fields:
        present_values = [row[field] for row in rows if row[field] not in (None, "")]
        missing_counts[field] = len(rows) - len(present_values)
        unique_values = {str(value) for value in present_values}
        if not unique_values:
            all_missing.append(field)
        elif len(unique_values) == 1:
            constant_observed.append(field)

    print(f"\n3. FEATURE: {len(fields)} cột A+B, trước preprocessing")
    print(f"  Trống hoàn toàn: {', '.join(all_missing) or 'không có'}")
    print("  Chỉ một giá trị khi có dữ liệu (missing vẫn có thể mang thông tin):")
    for field in constant_observed:
        print(f"    {field}")
    print("  12 cột thiếu nhiều nhất trên toàn bộ session:")
    for field, count in sorted(missing_counts.items(), key=lambda item: -item[1])[:12]:
        print(f"    {field:<32} {count:>7,}/{len(rows):,} ({100 * count / len(rows):.2f}%)")

    # Field TLS thiếu ở SSH/DB là bình thường; cần xem đúng nhóm giao thức.
    focus_fields = {
        "tls": ["tls_version", "tls_cipher", "tls_ja4", "cert_key_bits", "server_signature_scheme"],
        "ssh": ["ssh_kex", "ssh_cipher", "ssh_mac", "ssh_host_key_algorithm", "ssh_hassh"],
    }
    print("  Thiếu theo đúng giao thức:")
    for protocol, protocol_fields in focus_fields.items():
        protocol_rows = [row for row in rows if row["application_protocol"] == protocol]
        print(f"    {protocol.upper()}: {len(protocol_rows):,} session")
        for field in protocol_fields:
            if not protocol_rows:
                continue
            count = sum(row[field] in (None, "") for row in protocol_rows)
            print(f"      {field:<30} {100 * count / len(protocol_rows):6.2f}% thiếu")
    print("  TLS 1.3 có thể che certificate/signature; thiếu không tự động là lỗi sensor.")

    train_signatures = {tuple(str(row[field]) for field in fields) for row in splits["train"]}
    same_features = sum(
        tuple(str(row[field]) for field in fields) in train_signatures
        for row in splits["test"]
    )
    print(f"  Test có toàn bộ feature giống một mẫu train: {same_features:,}/{len(splits['test']):,}")
    print("  Feature giống nhau không đồng nghĩa trùng record hoặc chắc chắn có leakage.")


def print_lab_bias(rows, labels):
    print("\n4. DẤU HIỆU MODEL CÓ THỂ HỌC ĐẶC ĐIỂM LAB")
    for label in labels:
        label_rows = [row for row in rows if row["ground_truth_label"] == label]
        if not label_rows:
            continue
        without_crypto = sum(row["application_protocol"] not in {"tls", "ssh"} for row in label_rows)
        print(f"  {label}: {without_crypto:,}/{len(label_rows):,} mẫu không được nhận diện TLS/SSH")
        for field in ("dst_port", "tls_ja4"):
            counts = Counter(row[field] for row in label_rows if row[field] not in (None, ""))
            top_values = "; ".join(f"{value}: {count:,}" for value, count in counts.most_common(5))
            print(f"    Top {field}: {top_values or 'không có dữ liệu'}")
        certificate_counts = Counter(
            row["tls_certificate_trust"] for row in label_rows if row["tls_certificate_trust"]
        )
        print(f"    Certificate trust: {dict(certificate_counts)}")
    print("  Port/JA4 khác theo nhãn có thể giúp model nhận ra fixture/công cụ tạo traffic.")
    print("  Benign ghi untrusted: kiểm tra CA mà Zeek tin; chưa đủ để kết luận nhãn sai.")
    print("  Cân nhắc đánh giá bỏ port/fingerprint và đánh giá riêng TLS/SSH; không sửa nhãn dựa vào rule.")


def check_manifest(rows, summary, campaign_override):
    print("\n5. ĐỐI CHIẾU NHÃN VỚI MANIFEST (time window + role/endpoint)", flush=True)
    if campaign_override is not None:
        campaign = campaign_override.resolve()
    elif summary.get("source"):
        campaign = Path(summary["source"]).parent
        if not campaign.is_absolute():
            campaign = ROOT / campaign
    else:
        print("  SKIP: không xác định được campaign gốc; chưa kiểm tra nhãn với manifest.")
        return None

    manifest_path = campaign / "scenario_manifest.csv"
    baseline_path = campaign / ".internal/dataset/labeled_sessions.csv"
    hash_path = campaign / ".internal/public_checksums.json"
    baseline_hash_path = campaign / ".internal/dataset/checksums.json"
    required = [manifest_path, baseline_path, hash_path, baseline_hash_path, campaign / "dataset.csv"]
    if any(not path.is_file() for path in required):
        print(f"  SKIP: thiếu dữ liệu/manifest/checksum gốc tại {campaign}.")
        return None

    public_hashes = json.loads(hash_path.read_text(encoding="utf-8"))
    baseline_hashes = json.loads(baseline_hash_path.read_text(encoding="utf-8"))
    source_digest = checksum(campaign / "dataset.csv")
    if source_digest != public_hashes["dataset.csv"] or source_digest != summary["source_sha256"]:
        raise ValueError("Campaign gốc đã thay đổi hoặc không phải nguồn của subset")
    if checksum(manifest_path) != public_hashes["scenario_manifest.csv"]:
        raise ValueError("Checksum manifest không khớp")
    if checksum(baseline_path) != baseline_hashes["labeled_sessions.csv"]:
        raise ValueError("Checksum baseline gốc không khớp")

    windows_by_endpoint = defaultdict(list)
    for window in load_manifest(manifest_path):
        endpoint = (window["run_id"], window["src_role"], window["dst_role"])
        windows_by_endpoint[endpoint].append(window)
    roles = json.loads((ROOT / "experiments/lab_roles.json").read_text(encoding="utf-8"))
    selected = {(row["run_id"], row["uid"]): row for row in rows}
    seen = set()
    errors = Counter()
    for raw_row in iter_csv(baseline_path):
        session_key = (raw_row["run_id"], raw_row["uid"])
        if session_key not in selected:
            continue
        if session_key in seen:
            errors["duplicate_in_source"] += 1
        seen.add(session_key)
        row = selected[session_key]
        source_role, destination_role = resolve_roles(raw_row, roles)
        endpoint = (raw_row["run_id"], source_role, destination_role)
        candidates = [window for window in windows_by_endpoint[endpoint]
                      if not window.get("dst_port") or window["dst_port"] == raw_row["dst_port"]]
        # Dùng lại logic gắn nhãn của project, không tạo quy tắc ground truth thứ hai.
        window, status, _ = assign_label(raw_row, candidates, roles)
        if window is None:
            errors[status] += 1
        elif any(row[field] != window[field] for field in
                 ("scenario_id", "ground_truth_label", "src_role", "dst_role", "expected_behavior")):
            errors["manifest_label_or_identity_mismatch"] += 1
        elif row["ground_truth_label"] != raw_row["ground_truth_label"]:
            errors["baseline_label_mismatch"] += 1
    errors["missing_in_source"] += len(set(selected) - seen)
    errors = {reason: count for reason, count in errors.items() if count}
    print(f"  Đã đối chiếu: {len(seen):,}/{len(rows):,} session; lỗi: {sum(errors.values()):,}")
    for reason, count in errors.items():
        print(f"    {reason}: {count:,}")
    return not errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET_DIRECTORY, help="Thư mục subset có schema và splits")
    parser.add_argument("--campaign", type=Path, help="Campaign gốc nếu source đã chuyển chỗ")
    args = parser.parse_args()
    print(f"DATASET: {args.dataset.resolve()}", flush=True)
    print("CHECK: checksum, privacy, session/run trùng, nhãn và thời gian split...", flush=True)
    splits, summary = load_data(args.dataset.resolve(), training_config())
    print("PASS: checksum/privacy/schema; không trùng session/run giữa split; split khớp master và đúng thời gian.")
    rows = print_overview(splits, training_config()["labels"])
    print_feature_quality(rows, splits)
    print_lab_bias(rows, training_config()["labels"])
    manifest_ok = check_manifest(rows, summary, args.campaign)
    print("\nKẾT LUẬN:")
    if manifest_ok is False:
        print("  FAIL: nhãn/nguồn không khớp manifest; cần xử lý trước khi train.")
        return 1
    if manifest_ok is None:
        print("  WARN: cấu trúc/privacy/split đạt; ground truth chưa được đối chiếu lại.")
    else:
        print("  PASS kiểm tra tính toàn vẹn, privacy, split và nhãn với manifest.")
    print("  PASS không chứng minh dataset đại diện mạng thực tế; xem các hạn chế ở mục 1–4.")
    print("  Chỉ in console; không tạo file, không train, không thay đổi dataset.")
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
