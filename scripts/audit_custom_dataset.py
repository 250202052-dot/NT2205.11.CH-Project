"""Kiểm tra CSV thật: trùng session, manifest, missing và privacy.

Chỉ đọc dữ liệu thu gốc. Report nằm ở experiments/results/dataset_audit/.
Nhãn được đối chiếu bằng logic assign_label hiện có, không suy từ alert.
"""
import argparse
from collections import Counter, defaultdict
import csv
from itertools import zip_longest
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data.schemas.validate_zeek_metadata import validate_dataset
from src.features.label_sessions import assign_label, load_manifest, resolve_roles, checksum
from src.features.training_dataset import iter_csv, schema


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path, columns, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def check_hash(path, expected):
    if checksum(path) != expected:
        raise ValueError(f"Checksum mismatch: {path.name}")


def audit(campaign, output):
    output.mkdir(parents=True, exist_ok=True)
    internal = campaign / ".internal"
    state = json.loads((internal / "checkpoint.json").read_text())
    summary = json.loads((internal / "dataset/campaign_summary.json").read_text())
    if (campaign / ".campaign.lock").exists() or not summary["quota_complete"]:
        raise ValueError("Finish collection before auditing the final dataset")
    public = campaign / "dataset.csv"
    manifest_path = campaign / "scenario_manifest.csv"
    hashes = json.loads((internal / "public_checksums.json").read_text())
    for path in (public, manifest_path):
        check_hash(path, hashes[path.name])
    training = internal / "dataset/training"
    if checksum(public) != checksum(training / "labeled_sessions.csv"):
        raise ValueError("Public CSV differs from validated training export")
    baseline = internal / "dataset/labeled_sessions.csv"
    digests = json.loads((internal / "dataset/checksums.json").read_text())
    check_hash(baseline, digests["labeled_sessions.csv"])

    windows = defaultdict(list)
    for window in load_manifest(manifest_path):
        windows[window["run_id"]].append(window)
    roles = json.loads((ROOT / "experiments/lab_roles.json").read_text())
    # Cùng host role/port mới có khả năng khớp, giảm số window phải duyệt.
    indexed = defaultdict(list)
    for run, group in windows.items():
        for window in group:
            indexed[(run, window["src_role"], window["dst_role"])].append(window)
    provenance = {r["run_id"]: r["day"] for r in state["runs"] if r["status"] == "complete"}
    counts, scenarios, missing, totals = Counter(), Counter(), Counter(), Counter()
    seen, duplicate_count, errors, examples = set(), 0, Counter(), []
    with public.open(encoding="utf-8-sig", newline="") as handle:
        columns = csv.DictReader(handle).fieldnames
    if columns != schema()["columns"]:
        raise ValueError("Public CSV header does not match training schema")

    print("AUDIT: checking every session against manifest and counting missing fields", flush=True)
    for index, (row, raw) in enumerate(zip_longest(iter_csv(public), iter_csv(baseline)), 1):
        if row is None or raw is None:
            raise ValueError("Public/baseline row count differs")
        key = row["run_id"], row["uid"]
        if key in seen:
            duplicate_count += 1
        seen.add(key)
        if key != (raw["run_id"], raw["uid"]):
            raise ValueError("Public and baseline sessions are not aligned")
        label = row["ground_truth_label"]
        proto = row["application_protocol"] or "unknown"
        counts[label] += 1
        day = provenance.get(row["run_id"])
        if day is None:
            raise ValueError("Session belongs to an incomplete/unknown run")
        scenarios[(row["expected_behavior"], label, proto, day)] += 1
        src, dst = resolve_roles(raw, roles)
        candidates = [w for w in indexed[(row["run_id"], src, dst)]
                      if not w.get("dst_port") or w["dst_port"] == raw["dst_port"]]
        window, status, _ = assign_label(raw, candidates, roles)
        reason = None
        if window is None:
            reason = status
        elif any(row[field] != window[field] for field in ("scenario_id", "ground_truth_label", "src_role", "dst_role")):
            reason = "manifest_label_or_identity_mismatch"
        elif row["ground_truth_label"] != raw["ground_truth_label"]:
            reason = "baseline_label_mismatch"
        if reason:
            errors[reason] += 1
            if len(examples) < 10:
                examples.append({"run_id": key[0], "uid": key[1], "reason": reason})
        for group in ("all", proto):
            totals[group] += 1
            for field in columns:
                if row[field] == "":
                    missing[(group, field)] += 1
        if index % 25000 == 0:
            print(f"AUDIT: {index} sessions checked", flush=True)

    print("PRIVACY: running existing validate_zeek_metadata validator on final training export", flush=True)
    try:
        privacy = validate_dataset(training)
    except ValueError as error:
        privacy = {"passed": False, "error": str(error)}
    report = {"campaign_id": state["campaign_id"], "rows": sum(counts.values()), "class_counts": dict(counts),
        "duplicate_sessions": duplicate_count, "duplicate_definition": "Repeated (run_id, uid), not similar feature values",
        "manifest_errors": dict(errors), "manifest_error_examples": examples, "privacy": privacy,
        "source_sha256": {"dataset.csv": checksum(public), "scenario_manifest.csv": checksum(manifest_path)},
        "quota_complete": summary["quota_complete"],
        "passed": duplicate_count == 0 and not errors and privacy.get("passed", False),
        "note": "Missing is not automatically an error: TLS and SSH columns apply to different sessions; TLS1.3 cert can be invisible."}
    save_json(output / "audit.json", report)
    missing_rows = [{"protocol_group": group, "field": field, "missing": missing[(group, field)],
        "total": total, "missing_percent": round(100 * missing[(group, field)] / total, 3)}
        for group, total in sorted(totals.items()) for field in columns]
    write_csv(output / "missing_fields.csv", list(missing_rows[0]), missing_rows)
    scenario_rows = [dict(scenario=name, label=label, protocol=proto, block=day, sessions=count)
                     for (name, label, proto, day), count in sorted(scenarios.items())]
    write_csv(output / "scenario_counts.csv", list(scenario_rows[0]), scenario_rows)
    text = ["# Kết quả kiểm tra custom dataset", "", f"Tổng: {report['rows']:,} session.",
            f"Trùng session: {duplicate_count}. Sai mapping manifest: {sum(errors.values())}.",
            f"Privacy validator: {'PASS' if privacy.get('passed') else 'FAIL'}.", "",
            "Xem `scenario_counts.csv` để biết mẫu từng scenario/block.",
            "Xem `missing_fields.csv` theo protocol; field SSH trống ở TLS và ngược lại là bình thường.",
            "Các field trống nhiều không được tự điền số giả. Chưa kết luận dataset đủ tốt cho DL chỉ từ PASS.", ""]
    text += ["| Protocol | Field | Thiếu (%) |", "|---|---|---:|"]
    focus = {"tls": {"tls_version", "tls_cipher", "tls_ja4", "cert_key_bits", "cert_signature_algorithm", "cert_spki_token", "server_signature_scheme"},
             "ssh": {"ssh_version", "ssh_kex", "ssh_cipher", "ssh_mac", "ssh_host_key_algorithm", "ssh_hassh", "ssh_ja4ssh"}}
    for row in missing_rows:
        if row["field"] in focus.get(row["protocol_group"], set()):
            text.append(f"| {row['protocol_group']} | {row['field']} | {row['missing_percent']} |")
    (output / "README.md").write_text("\n".join(text), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=ROOT / "data/lab_metadata/campaigns/custom_data_v1")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/dataset_audit/custom_data_v1")
    args = parser.parse_args()
    report = audit(args.campaign.resolve(), args.output.resolve())
    if not report["passed"]:
        raise SystemExit("FAIL audit; read audit.json before training")


if __name__ == "__main__":
    main()
