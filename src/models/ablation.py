"""Chạy A/B/C trên cùng dataset và split, không thay dữ liệu thu gốc.

Mặc định chỉ audit (kiểm tra); thêm --train mới huấn luyện.
Đọc report/CUSTOM_DATASET_AUDIT_ABLATION.md trước khi chạy lần đầu.
"""

from collections import Counter
import csv
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]

# Tái sử dụng validator và schema hiện có, không viết bộ đọc Zeek khác.
from data.schemas.validate_zeek_metadata import validate_dataset
from src.features.build_sessions import CONNECTION_FIELDS, CSV_COLUMNS
from src.features.flow_context import enrich_flows, DERIVED_FLOW_FIELDS, FLOW_FEATURE_VERSION
from src.features.label_sessions import LABELS, checksum


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def project_path(value):
    """Config dùng đường dẫn tương đối từ project-root, không từ cwd tùy ý."""
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


# Feature Definitions
# -----------------------------------------------------------------------------
def feature_groups(spec):
    """C phải đúng A+B. Chặn cột nhãn/rule/ID dù người dùng sửa config."""
    groups = {}
    flow_allowed = (set(CONNECTION_FIELDS) - {"src_ip", "dst_ip", "src_port", "ssh_ja4ssh"}) | set(DERIVED_FLOW_FIELDS)
    crypto_allowed = {c for c in CSV_COLUMNS if c.startswith(("tls_", "ssh_", "cert_"))}
    blocked = set(spec["excluded_columns"])
    if spec.get("feature_set_version") == "ablation-training-v2":
        from src.features.ablation_training import FLOW_EXTENSIONS, CRYPTO_EXTENSIONS
        from src.features.training_dataset import schema
        flow_allowed |= FLOW_EXTENSIONS
        crypto_allowed |= CRYPTO_EXTENSIONS
        blocked |= set(schema()["exclude_from_model_inputs"])
    # Các trường dưới đây tuyệt đối không được dùng dự đoán ground truth.
    blocked |= {"ground_truth_label", "scenario_id", "run_id", "uid", "expected_rule", "expected_behavior",
                "observed_rules", "expected_rule_observed", "notice_count", "tls_policy_violations",
                "ssh_policy_violations", "tls_policy_version", "ssh_policy_version", "cert_fingerprint",
                "cert_spki_sha256", "ssh_host_key_fingerprint", "cert_issuer_name_sha256"}
    for name, allowed in (("A", flow_allowed), ("B", crypto_allowed)):
        group = spec["groups"][name]
        fields = group["numeric"] + group["categorical"]
        if not fields or len(fields) != len(set(fields)) or set(fields) - allowed or set(fields) & blocked:
            raise ValueError(f"Invalid or leaking feature selection in {name}")
        groups[name] = {kind: list(group[kind]) for kind in ("numeric", "categorical")}
    if spec["groups"]["C"].get("union") != ["A", "B"]:
        raise ValueError("C must be the exact union of A and B")
    groups["C"] = {kind: groups["A"][kind] + groups["B"][kind] for kind in ("numeric", "categorical")}
    return groups


# Data Validation & Loading
# -----------------------------------------------------------------------------
def verify_checksums(directory):
    """Phát hiện dữ liệu tổng hợp bị sửa trước khi làm thí nghiệm."""
    digests = json.loads((directory / "checksums.json").read_text(encoding="utf-8"))
    required = ["labeled_sessions.csv", "schema.json", "campaign_summary.json"]
    for name in ("train", "validation", "test"):
        required += [str(Path("splits") / name / file) for file in ("labeled_sessions.csv", "schema.json")]
    for name in ("full_collection", "context"):
        if name == "full_collection" or (directory / name).exists():
            required += [str(Path(name) / file) for file in ("labeled_sessions.csv", "schema.json")]
    # Checksum manifest có thể dùng slash Windows hoặc slash POSIX.
    normalized = {name.replace("\\", "/") for name in digests}
    if any(name.replace("\\", "/") not in normalized for name in required):
        raise ValueError("Missing checksum for an ablation source file")
    for name, expected in digests.items():
        target = (directory / name.replace("\\", "/")).resolve()
        if not target.is_relative_to(directory.resolve()) or checksum(target) != expected:
            raise ValueError(f"Dataset checksum mismatch: {name}")


def session_key(row):
    return row["run_id"], row["uid"]


def load_data(directory, config):
    """Giữ split đã có, không random từng dòng hoặc tạo split thay thế."""
    specification = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    if specification.get("schema_version") == "lab-training-v2":
        from src.features.ablation_training import load_training_data
        return load_training_data(directory, config)
    validate_dataset(directory)
    verify_checksums(directory)
    summary = json.loads((directory / "campaign_summary.json").read_text(encoding="utf-8"))
    if config["require_complete_quota"] and not summary["quota_complete"]:
        raise ValueError("Campaign quota incomplete; finish collection or use an explicitly separate pilot config")
    master = read_csv(directory / "labeled_sessions.csv")
    master_index = {session_key(row): row for row in master}
    if len(master_index) != len(master) or any(row["application_protocol"] not in {"tls", "ssh"} for row in master):
        raise ValueError("Master dataset must contain unique TLS/SSH sessions")
    splits, seen_keys, seen_runs = {}, set(), set()
    for name in ("train", "validation", "test"):
        folder = directory / "splits" / name
        validate_dataset(folder)
        rows = read_csv(folder / "labeled_sessions.csv")
        keys = {session_key(row) for row in rows}
        runs = {row["run_id"] for row in rows}
        if len(keys) != len(rows) or keys & seen_keys or runs & seen_runs:
            raise ValueError("Duplicate session or shared run across splits")
        if any(master_index.get(session_key(row)) != row for row in rows):
            raise ValueError("Split data differs from master dataset")
        labels = Counter(row["ground_truth_label"] for row in rows)
        if config["require_all_labels_per_split"] and set(labels) != set(config["labels"]):
            raise ValueError(f"{name} missing labels: {sorted(set(config['labels']) - set(labels))}")
        splits[name] = rows
        seen_keys.update(keys)
        seen_runs.update(runs)
    if seen_keys != set(master_index):
        raise ValueError("Splits must exactly partition the master dataset")
    for earlier, later in (("train", "validation"), ("validation", "test")):
        if max(float(r["timestamp_unix"]) for r in splits[earlier]) > min(float(r["timestamp_unix"]) for r in splits[later]):
            raise ValueError("Splits are not chronological")

    # Không tính window từ subset quota đã sampling: dùng collection đầy đủ.
    # Giữ context HTTP/DB để đếm hoạt động nguồn; chỉ TLS/SSH là mẫu ML.
    observation = []
    for name in ("full_collection", "context"):
        folder = directory / name
        if name == "full_collection" or folder.exists():
            validate_dataset(folder)
            observation.extend(read_csv(folder / "labeled_sessions.csv"))
    if len({session_key(row) for row in observation}) != len(observation):
        raise ValueError("Duplicate session in observation pool")
    observation_index = {session_key(row): row for row in observation}
    if any(observation_index.get(key) != row for key, row in master_index.items()):
        raise ValueError("Selected session missing or changed in full collection")
    enriched = {}
    for name, rows in splits.items():
        run_ids = {r["run_id"] for r in rows}
        # Run không được chia giữa các split, nên window cũng không vượt split.
        pool = [r for r in observation if r["run_id"] in run_ids]
        lookup = {session_key(r): r for r in enrich_flows(pool)}
        enriched[name] = [lookup[session_key(r)] for r in rows]
    return enriched, summary


# Evaluation & Results
# -----------------------------------------------------------------------------
def metrics(truth, predicted, labels, attack_scores=None):
    from sklearn.metrics import (accuracy_score, average_precision_score, classification_report,
                                 confusion_matrix, f1_score, matthews_corrcoef, recall_score)
    benign_total = sum(label == "benign" for label in truth)
    # Positive = attack_behavior; ba lớp còn lại là negative cho TPR/FPR này.
    attack_total = sum(label == "attack_behavior" for label in truth)
    nonattack_total = len(truth) - attack_total
    true_positives = sum(t == "attack_behavior" and p == "attack_behavior" for t, p in zip(truth, predicted))
    false_positives = sum(t != "attack_behavior" and p == "attack_behavior" for t, p in zip(truth, predicted))
    return {"macro_f1": float(f1_score(truth, predicted, labels=labels, average="macro", zero_division=0)),
            "accuracy": float(accuracy_score(truth, predicted)),
            "macro_recall": float(recall_score(truth, predicted, labels=labels, average="macro", zero_division=0)),
            "mcc": float(matthews_corrcoef(truth, predicted)),
            "ap_attack": float(average_precision_score(
                [label == "attack_behavior" for label in truth], attack_scores
            )) if attack_scores is not None and attack_total else None,
            "tpr_attack": true_positives / attack_total if attack_total else None,
            "fpr_attack": false_positives / nonattack_total if nonattack_total else None,
            "per_class": classification_report(truth, predicted, labels=labels, output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(truth, predicted, labels=labels).tolist(),
            "confusion_label_order": labels,
            "benign_false_alarm_rate": (sum(t == "benign" and p != "benign" for t, p in zip(truth, predicted)) / benign_total) if benign_total else None}


def train(splits, groups, config, output):
    """Chỉ thay nhóm feature; toàn bộ quy trình học dùng code baseline."""
    # Import khi gọi để baseline vẫn dùng được reader/metrics trong file này.
    from src.models.baselines import train_models
    return train_models(splits, groups, config, output)


def new_result_folder(parent):
    """Đánh số dễ đọc; tạo độc quyền để không ghi đè kết quả cũ."""
    parent.mkdir(parents=True, exist_ok=True)
    numbers = [int(p.name.removeprefix("ketqua_lan")) for p in parent.iterdir()
               if p.name.startswith("ketqua_lan") and p.name.removeprefix("ketqua_lan").isdigit()]
    number = max(numbers, default=0) + 1
    while True:
        folder = parent / f"ketqua_lan{number}"
        try:
            folder.mkdir()
            return folder
        except FileExistsError:
            number += 1


def write_summary(results, groups, model_names, output):
    """Tổng hợp metrics qua seed, chỉ xuất một CSV kết quả."""
    summary = []
    for group_name in groups:
        for name in model_names:
            runs = [r for r in results if r["feature_group"] == group_name and r["model"] == name]
            scores = [r["test"]["macro_f1"] for r in runs]
            summary.append(dict(
                feature_group=group_name,
                model=name,
                accuracy_mean=statistics.mean(r["test"]["accuracy"] for r in runs),
                recall_macro_mean=statistics.mean(r["test"]["macro_recall"] for r in runs),
                macro_f1_mean=statistics.mean(scores),
                mcc_mean=statistics.mean(r["test"]["mcc"] for r in runs),
                ap_attack_mean=statistics.mean(r["test"]["ap_attack"] for r in runs),
                tpr_attack_mean=statistics.mean(r["test"]["tpr_attack"] for r in runs),
                fpr_attack_mean=statistics.mean(r["test"]["fpr_attack"] for r in runs),
                train_seconds_mean=statistics.mean(r["fit_seconds"] for r in runs),
                predict_seconds_mean=statistics.mean(r["test_prediction_seconds"] for r in runs),
            ))
    with (output / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)


# Main Workflow
# -----------------------------------------------------------------------------
def run_ablation(dataset=None, train_models=False, config_path=None):
    from src.models.baselines import DATASET_DIRECTORY, get_feature_groups, training_config
    config = training_config()
    groups = get_feature_groups()
    directory = DATASET_DIRECTORY
    output_directory = ROOT / "experiments/results/custom_ablation"
    if config_path is not None:
        # Giữ --config cho lệnh cũ; mặc định không cần JSON cấu hình model.
        overrides = json.loads(config_path.read_text(encoding="utf-8"))
        config.update(overrides)
        config["seeds"] = [42]
        if "models" not in overrides and "model" in overrides:
            old = overrides["model"]
            if old["name"] != "random_forest":
                raise ValueError("Legacy config only supports random_forest")
            config["models"] = {"random_forest": {
                "n_estimators": old["n_estimators"], "min_samples_leaf": old["min_samples_leaf"],
                "max_depth": old["max_depth_candidates"][0],
            }}
            config["n_jobs"] = old["n_jobs"]
        if "feature_config" in overrides:
            groups = feature_groups(json.loads(project_path(overrides["feature_config"]).read_text(encoding="utf-8")))
        directory = project_path(config.get("dataset_directory", directory))
        output_directory = project_path(config.get("output_directory", output_directory))
    if set(config["labels"]) != LABELS or len(config["labels"]) != len(LABELS):
        raise ValueError("Use exactly the four project labels")
    if dataset is not None:
        directory = dataset.resolve()
    print("AUDIT: checksum, privacy, labels, chronological split", flush=True)
    splits, _ = load_data(directory, config)
    if not train_models:
        print("PASS ablation audit; no output files created")
        return
    output = new_result_folder(output_directory)
    try:
        results = train(splits, groups, config, output)
    except BaseException:
        if not any(output.iterdir()):
            output.rmdir()
        raise
    print(f"PASS ablation; output: {output}")
    return results

