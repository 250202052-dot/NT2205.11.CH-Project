"""Chọn benign đa dạng và chia theo block, giữ nguyên dữ liệu thu gốc.

Không tính lại flow/history từ subset: giữ feature đã tính từ collection đầy đủ.
Không SMOTE/pad, không random-split từng session qua các block.
"""
import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import heapq
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.audit_custom_dataset import save_json
from src.features.label_sessions import checksum
from src.features.training_dataset import iter_csv, write_export, schema, decode


def allocate(counts, target):
    """Phân số mẫu theo tỷ lệ nhóm; giữ ít nhất một mẫu mỗi nhóm nếu đủ quota."""
    if target < len(counts) or target > sum(counts.values()):
        raise ValueError("Benign target cannot cover strata or exceeds available sessions")
    result = dict.fromkeys(counts, 1)
    remaining = target - len(counts)
    capacity = {key: count - 1 for key, count in counts.items()}
    total = sum(capacity.values())
    if not total:
        return result
    shares = {key: Fraction(remaining * cap, total) for key, cap in capacity.items()}
    for key, share in shares.items():
        result[key] += int(share)
    extra = target - sum(result.values())
    order = sorted(shares, key=lambda key: (-(shares[key] - int(shares[key])), key))
    for key in order[:extra]:
        result[key] += 1
    return result


def prepare(campaign, audit_path, output, seed=2205, refresh=False):
    report = json.loads(audit_path.read_text())
    source = campaign / "dataset.csv"
    if not report["passed"] or report["source_sha256"]["dataset.csv"] != checksum(source):
        raise ValueError("Run a successful audit on the unchanged source before preparing")
    if output.exists() and not refresh:
        raise ValueError("Prepared directory exists; use a new output path to preserve experiments")
    state = json.loads((campaign / ".internal/checkpoint.json").read_text())
    days = {r["run_id"]: r["day"] for r in state["runs"] if r["status"] == "complete"}
    quotas = {d["day"]: d["targets"]["benign"] for d in state["config"]["days"]}
    strata = defaultdict(Counter)
    for row in iter_csv(source):
        if row["ground_truth_label"] == "benign":
            strata[days[row["run_id"]]][(row["application_protocol"], row["expected_behavior"])] += 1
    allocation = {day: allocate(counts, quotas[day]) for day, counts in strata.items()}
    heaps = defaultdict(list)
    print("PREPARE: choose real benign sessions by block/protocol/behavior with a fixed seed", flush=True)
    for row in iter_csv(source):
        if row["ground_truth_label"] != "benign":
            continue
        day = days[row["run_id"]]
        stratum = row["application_protocol"], row["expected_behavior"]
        quota = allocation[day][stratum]
        key = row["run_id"], row["uid"]
        # Hash ranking có thể tái lập, không phụ thuộc thứ tự file.
        rank = int.from_bytes(hashlib.sha256(f"{seed}|{key[0]}|{key[1]}".encode()).digest(), "big")
        heap = heaps[(day, stratum)]
        item = -rank, key
        if len(heap) < quota:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)
    chosen = {key for heap in heaps.values() for _, key in heap}
    selected, splits = [], defaultdict(list)
    types = schema()["types"]
    for raw in iter_csv(source):
        if raw["ground_truth_label"] == "benign" and (raw["run_id"], raw["uid"]) not in chosen:
            continue
        row = {field: decode(raw[field], kind) for field, kind in types.items()}
        day = days[row["run_id"]]
        split = "train" if day <= 3 else "validation" if day == 4 else "test"
        selected.append(row)
        splits[split].append(row)
    if set(splits) != {"train", "validation", "test"}:
        raise ValueError("Need all three chronological splits")
    if refresh:
        # Only refresh an existing prepared dataset, never an arbitrary directory.
        if not output.resolve().is_relative_to((ROOT / "experiments/datasets").resolve()):
            raise ValueError("Refresh target must stay inside experiments/datasets")
        if not (output / "preparation_summary.json").is_file():
            raise ValueError("Refresh requires an existing prepared dataset")
    output.mkdir(parents=True, exist_ok=refresh)
    write_export(output, selected)
    for split, rows in splits.items():
        if set(r["ground_truth_label"] for r in rows) != set(report["class_counts"]):
            raise ValueError(f"{split} does not contain every label")
        write_export(output / "splits" / split, rows)
    result = {"campaign_id": state["campaign_id"], "source": str(source), "source_sha256": checksum(source),
        "source_audit_sha256": checksum(audit_path), "quota_complete": report["quota_complete"],
        "clock_mode": state["mode"], "rows": len(selected), "seed": seed,
        "class_counts": dict(Counter(r["ground_truth_label"] for r in selected)),
        "split_counts": {split: dict(Counter(r["ground_truth_label"] for r in rows)) for split, rows in splits.items()},
        "selection": "Keep all abnormal; sample genuine benign within each block/protocol/behavior. No duplicates/SMOTE.",
        "history": "Existing features retained from full observations, not recomputed from sampled subset; reset per source run",
        "limitations": ["Closed lab topology and fixture ports can be shortcuts; temporal split is not cross-dataset or unseen-host evaluation.",
                        "Some related flows/scenarios repeat across different runs; this is chronological validation, not unseen-scenario validation."]}
    save_json(output / "preparation_summary.json", result)
    save_json(output / "checksums.json", {str(p.relative_to(output)): checksum(p)
        for p in output.rglob("*") if p.is_file() and p.name != "checksums.json"})
    print(json.dumps(result, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=ROOT / "data/lab_metadata/campaigns/custom_data_v1")
    parser.add_argument("--audit", type=Path, default=ROOT / "experiments/results/dataset_audit/custom_data_v1/audit.json")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/datasets/custom_data_v1_ablation")
    parser.add_argument("--refresh", action="store_true", help="Update the same prepared folder after supplement/audit; creates no version folder")
    args = parser.parse_args()
    prepare(args.campaign.resolve(), args.audit.resolve(), args.output.resolve(), refresh=args.refresh)


if __name__ == "__main__":
    main()
