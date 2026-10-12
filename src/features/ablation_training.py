"""Adapter schema lab-training-v2 cho runner A/B/C hiện có.

Không ghép Zeek lần nữa. Vector gói được biến thành thống kê của chính session,
không dùng nhãn hoặc dữ liệu session tương lai để tạo feature.
"""
from collections import Counter
import json
import statistics

from data.schemas.validate_zeek_metadata import validate_dataset
from src.features.label_sessions import checksum
from src.features.training_dataset import read_csv

FLAG_NAMES = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"]
PACKET_SUMMARIES = ["packet_size_mean", "packet_size_std", "packet_size_min", "packet_size_max"]
FLAG_FIELDS = [f"tcp_{direction}_{flag}" for direction in ("orig", "resp") for flag in FLAG_NAMES]
FLOW_EXTENSIONS = set(PACKET_SUMMARIES + FLAG_FIELDS + ["orig_iat_mean", "orig_iat_std", "resp_iat_mean", "resp_iat_std"])
CRYPTO_EXTENSIONS = {"client_extensions", "server_extensions", "client_signature_schemes", "server_signature_scheme",
                     "ech_observed", "client_hello_observed", "server_hello_observed"}


def vector(value):
    return json.loads(value) if value not in (None, "") else []


def enrich_packet_vector(row):
    result = dict(row)
    sizes = vector(row.get("pkt_size_vector"))
    values = [statistics.mean(sizes), statistics.pstdev(sizes), min(sizes), max(sizes)] if sizes else [None] * 4
    result.update(zip(PACKET_SUMMARIES, values))
    for direction in ("orig", "resp"):
        flags = vector(row.get(f"tcp_flags_{direction}"))
        if flags and len(flags) != 8:
            raise ValueError("Unexpected TCP flag vector length")
        for index, flag in enumerate(FLAG_NAMES):
            result[f"tcp_{direction}_{flag}"] = flags[index] if flags else None
    return result


def load_training_data(directory, config):
    # Checksum kiểm tra cả master và split, không chỉ tin tên folder.
    digests = json.loads((directory / "checksums.json").read_text())
    normalized = {name.replace("\\", "/"): value for name, value in digests.items()}
    required = ["labeled_sessions.csv", "schema.json", "preparation_summary.json"]
    required += [f"splits/{split}/{name}" for split in ("train", "validation", "test")
                 for name in ("labeled_sessions.csv", "schema.json")]
    if any(name not in normalized for name in required):
        raise ValueError("Prepared dataset is missing checksums")
    for name, digest in normalized.items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or checksum(path) != digest:
            raise ValueError(f"Prepared dataset checksum mismatch: {name}")
    summary = json.loads((directory / "preparation_summary.json").read_text())
    if config["require_complete_quota"] and not summary["quota_complete"]:
        raise ValueError("Campaign quota incomplete")
    validate_dataset(directory)
    master = read_csv(directory / "labeled_sessions.csv")
    master_index = {(r["run_id"], r["uid"]): r for r in master}
    if len(master_index) != len(master):
        raise ValueError("Duplicate master session")
    splits, seen, seen_runs = {}, set(), set()
    for split in ("train", "validation", "test"):
        folder = directory / "splits" / split
        validate_dataset(folder)
        rows = read_csv(folder / "labeled_sessions.csv")
        keys = {(r["run_id"], r["uid"]) for r in rows}
        runs = {r["run_id"] for r in rows}
        if len(keys) != len(rows) or keys & seen or runs & seen_runs:
            raise ValueError("Shared run/session across chronological splits")
        if any(master_index.get((r["run_id"], r["uid"])) != r for r in rows):
            raise ValueError("Split differs from master")
        if config["require_all_labels_per_split"] and set(Counter(r["ground_truth_label"] for r in rows)) != set(config["labels"]):
            raise ValueError(f"Missing labels in {split}")
        splits[split] = [enrich_packet_vector(r) for r in rows]
        seen.update(keys)
        seen_runs.update(runs)
    if seen != set(master_index):
        raise ValueError("Splits do not exactly partition master")
    for earlier, later in (("train", "validation"), ("validation", "test")):
        last_end = max(float(r["timestamp_unix"]) + float(r["duration_seconds"] or 0) for r in splits[earlier])
        first_start = min(float(r["timestamp_unix"]) for r in splits[later])
        if last_end > first_start:
            raise ValueError("Chronological splits overlap")
    return splits, summary
