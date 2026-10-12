"""So sánh RF/XGBoost/LightGBM trên cùng split và feature metadata.

Không thu traffic, không sửa CSV gốc. Mặc định audit; --train để huấn luyện.
"""
from collections import Counter
from pathlib import Path
from time import perf_counter

# Tái sử dụng split, validator, feature allowlist và metrics của A/B/C.
from src.models.ablation import feature_groups, load_data, metrics, new_result_folder, write_summary
from src.features.label_sessions import LABELS


# Configuration
# -----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
DATASET_DIRECTORY = ROOT / "experiments/datasets/custom_data_v1_ablation"
OUTPUT_DIRECTORY = ROOT / "experiments/results/model_baselines"
SEEDS = [42]
CV_SPLITS = 3
N_JOBS = 2
LABEL_NAMES = ["benign", "misconfiguration", "policy_violation", "attack_behavior"]
MODEL_PARAMETERS = {
    "random_forest": {"n_estimators": 100, "max_depth": 12, "min_samples_leaf": 2},
    "xgboost": {"n_estimators": 100, "max_depth": 6, "learning_rate": 0.1},
    "lightgbm": {"n_estimators": 100, "num_leaves": 31, "learning_rate": 0.1},
}


MIN_CATEGORY_FREQUENCY = 5  # Nhóm giá trị chữ xuất hiện <5 lần trong train.
LOG_COLUMNS = {
    "duration_seconds", "src_bytes", "dst_bytes", "src_packets", "dst_packets",
    "missed_bytes", "flow_total_bytes", "flow_total_packets", "flow_bytes_per_second",
    "flow_packets_per_second", "flow_source_connections_10s", "flow_source_connections_60s",
    "flow_source_unique_destinations_60s", "flow_source_unique_ports_60s",
    "orig_iat_mean", "orig_iat_std", "resp_iat_mean", "resp_iat_std", "ssh_auth_attempts",
}


def training_config():
    """Baseline và ablation dùng cùng tham số và cách kiểm tra dữ liệu."""
    return {
        "labels": LABEL_NAMES, "seeds": SEEDS, "n_jobs": N_JOBS,
        "models": MODEL_PARAMETERS, "cv_splits": CV_SPLITS,
        "require_all_labels_per_split": True, "require_complete_quota": True,
    }


# Feature Definitions
# -----------------------------------------------------------------------------
# Giữ đúng feature của A/B/C cũ để so sánh công bằng.
A_NUMERIC = [
    "duration_seconds",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "missed_bytes",
    "flow_total_bytes",
    "flow_total_packets",
    "flow_bytes_per_second",
    "flow_packets_per_second",
    "flow_src_byte_fraction",
    "flow_duration_missing_or_zero",
    "flow_source_connections_10s",
    "flow_source_connections_60s",
    "flow_source_unique_destinations_60s",
    "flow_source_unique_ports_60s",
    "orig_iat_mean",
    "orig_iat_std",
    "resp_iat_mean",
    "resp_iat_std",
    "packet_size_mean",
    "packet_size_std",
    "packet_size_min",
    "packet_size_max",
    "tcp_orig_fin",
    "tcp_orig_syn",
    "tcp_orig_rst",
    "tcp_orig_psh",
    "tcp_orig_ack",
    "tcp_orig_urg",
    "tcp_orig_ece",
    "tcp_orig_cwr",
    "tcp_resp_fin",
    "tcp_resp_syn",
    "tcp_resp_rst",
    "tcp_resp_psh",
    "tcp_resp_ack",
    "tcp_resp_urg",
    "tcp_resp_ece",
    "tcp_resp_cwr",
]
A_CATEGORICAL = [
    "dst_port",
    "transport_protocol",
    "connection_state",
    "flow_history",
]
B_NUMERIC = [
    "tls_established",
    "tls_resumed",
    "tls_certificate_visible",
    "tls_chain_length",
    "tls_hostname_matches",
    "cert_key_bits",
    "cert_validity_days",
    "cert_remaining_days_at_session",
    "cert_san_dns_count",
    "cert_san_ip_count",
    "ssh_version",
    "ssh_auth_attempts",
    "ssh_auth_success_inferred",
    "client_hello_observed",
    "server_hello_observed",
    "ech_observed",
    "server_signature_scheme",
]
B_CATEGORICAL = [
    "tls_version",
    "tls_cipher",
    "tls_curve",
    "tls_handshake_status",
    "tls_last_alert",
    "tls_certificate_trust",
    "tls_certificate_validity",
    "tls_ja3",
    "tls_ja3s",
    "tls_ja4",
    "tls_ja4s",
    "cert_key_type",
    "cert_signature_algorithm",
    "cert_issuer_class",
    "ssh_client",
    "ssh_server",
    "ssh_kex",
    "ssh_cipher",
    "ssh_mac",
    "ssh_mac_effective",
    "ssh_host_key_algorithm",
    "ssh_hassh",
    "ssh_hassh_server",
    "ssh_ja4ssh",
    "client_extensions",
    "server_extensions",
    "client_signature_schemes",
]


def get_feature_groups():
    # Tái sử dụng allowlist hiện có để chặn nhãn/ID/rule đi vào input model.
    spec = {
        "feature_set_version": "ablation-training-v2", "excluded_columns": [],
        "groups": {
            "A": {"numeric": A_NUMERIC, "categorical": A_CATEGORICAL},
            "B": {"numeric": B_NUMERIC, "categorical": B_CATEGORICAL},
            "C": {"union": ["A", "B"]},
        },
    }
    return feature_groups(spec)


# Data Preprocessing
# -----------------------------------------------------------------------------
def numeric_array(rows, fields):
    """Đọc số; missing/non-finite thành NaN. Chuỗi số sai thì báo lỗi."""
    import numpy as np
    values = np.full((len(rows), len(fields)), np.nan, dtype=float)
    for i, row in enumerate(rows):
        for j, field in enumerate(fields):
            value = row[field]
            if value is None or value == "":
                continue
            if str(value).lower() in {"true", "false"}:
                value = str(value).lower() == "true"
            number = float(value)
            if not np.isfinite(number):
                continue
            # Bytes/count/duration/IAT không được âm; không áp dụng cho số ngày cert.
            if field in LOG_COLUMNS:
                if number < 0:
                    raise ValueError(f"Giá trị âm không hợp lệ: {field}={number}")
                number = np.log1p(number)
            values[i, j] = number
    return values


def categorical_array(rows, fields):
    """Missing có nhóm riêng; chỉ bỏ khoảng trắng ở hai đầu chuỗi."""
    import numpy as np
    result = []
    for row in rows:
        values = []
        for field in fields:
            value = "" if row[field] is None else str(row[field]).strip()
            values.append(value or "__MISSING__")
        result.append(values)
    return np.array(result, dtype=object).reshape(len(rows), len(fields))


def prepare_features(splits, group, return_preprocessor=False):
    """Các bước tiền xử lý cơ bản; không sửa CSV, không học từ validation/test."""
    import numpy as np
    from sklearn.preprocessing import OneHotEncoder
    numbers = {s: numeric_array(rows, group["numeric"]) for s, rows in splits.items()}
    train = numbers["train"]
    # Trung vị tính riêng từng cột train; cột trống hoàn toàn dùng 0 + missing flag.
    medians = []
    for column in train.T:
        present = column[~np.isnan(column)]
        medians.append(float(np.median(present)) if len(present) else 0.0)
    medians = np.array(medians)
    encoded = {}
    if group["categorical"]:
        categories = {s: categorical_array(rows, group["categorical"]) for s, rows in splits.items()}
        encoder = OneHotEncoder(handle_unknown="infrequent_if_exist",
                                min_frequency=MIN_CATEGORY_FREQUENCY, sparse_output=False)
        encoded["train"] = encoder.fit_transform(categories["train"])
        for split in splits:
            if split == "train":
                continue
            encoded[split] = encoder.transform(categories[split])
    output = {}
    for split, values in numbers.items():
        missing = np.isnan(values)
        filled = np.where(missing, medians, values)
        parts = [filled, missing.astype(float)]
        if group["categorical"]:
            parts.append(encoded[split])
        # Dense cho ba model: giá trị 0 thật không bị sparse representation bỏ mất.
        output[split] = np.hstack(parts).astype(np.float32)
        if not np.isfinite(output[split]).all():
            raise ValueError("Feature vượt giới hạn float32")
    print(f"PREPROCESS: {len(group['numeric'])} numeric + missing flags, "
          f"{len(group['categorical'])} categorical -> {output['train'].shape[1]} columns", flush=True)
    if return_preprocessor:
        preprocessor = {
            "numeric_fields": list(group["numeric"]),
            "categorical_fields": list(group["categorical"]),
            "numeric_medians": medians,
            "categorical_encoder": encoder if group["categorical"] else None,
            "log_columns": set(LOG_COLUMNS),
        }
        return output, preprocessor
    return output


def transform_with_preprocessor(rows, preprocessor):
    """Apply the preprocessing saved with an exported model to new sessions."""
    import numpy as np

    numeric_fields = preprocessor["numeric_fields"]
    categorical_fields = preprocessor["categorical_fields"]
    medians = preprocessor["numeric_medians"]
    encoder = preprocessor["categorical_encoder"]

    # Live Zeek rows do not contain ground truth/provenance columns. Missing model
    # fields stay missing and follow the same rules used during training.
    model_rows = [
        {field: row.get(field) for field in numeric_fields + categorical_fields}
        for row in rows
    ]
    numbers = numeric_array(model_rows, numeric_fields)
    missing = np.isnan(numbers)
    parts = [np.where(missing, medians, numbers), missing.astype(float)]
    if categorical_fields:
        categories = categorical_array(model_rows, categorical_fields)
        parts.append(encoder.transform(categories))

    transformed = np.hstack(parts).astype(np.float32)
    if not np.isfinite(transformed).all():
        raise ValueError("Feature vượt giới hạn float32")
    return transformed


# Model Training
# -----------------------------------------------------------------------------
def chronological_folds(rows, labels, n_splits):
    """Chia theo run và giờ thật: học quá khứ, đánh giá phần tiếp theo."""
    from sklearn.model_selection import TimeSeriesSplit
    by_run = {}
    for row in rows:
        by_run.setdefault(row["run_id"], []).append(row)
    runs = sorted(by_run, key=lambda run: min(float(r["timestamp_unix"]) for r in by_run[run]))
    if n_splits < 2 or len(runs) <= n_splits:
        raise ValueError("Cross-validation cần ít nhất 2 folds và đủ run độc lập")
    folds = []
    for train_indices, validation_indices in TimeSeriesSplit(n_splits=n_splits).split(runs):
        train_rows = [r for i in train_indices for r in by_run[runs[i]]]
        validation_rows = [r for i in validation_indices for r in by_run[runs[i]]]
        if {r["ground_truth_label"] for r in train_rows} != set(labels):
            raise ValueError("CV train thiếu nhãn: đoạn đầu chỉ benign; giảm CV_SPLITS hoặc cần thêm run có đủ bốn nhãn")
        last_end = max(float(r["timestamp_unix"]) + float(r["duration_seconds"] or 0) for r in train_rows)
        first_start = min(float(r["timestamp_unix"]) for r in validation_rows)
        if last_end > first_start:
            raise ValueError("CV train/validation chồng lấn thời gian session")
        folds.append({"train": train_rows, "validation": validation_rows})
    return folds


def make_model(name, candidate, seed, threads, n_classes):
    """Các model nhận cùng X và sample_weight; không nhân đôi class weight."""
    parameters = dict(candidate, random_state=seed, n_jobs=threads)
    if name == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(**parameters)
    if name == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(**parameters, objective="multi:softprob", num_class=n_classes,
                             tree_method="hist", eval_metric="mlogloss", verbosity=0)
    if name == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(**parameters, objective="multiclass", num_class=n_classes,
                              deterministic=True, force_col_wise=True, verbosity=-1)
    raise ValueError(f"Unknown model: {name}")


def cross_validate_models(folds, group, group_name, config):
    """Fit lại preprocessing và trọng số trong từng fold; không dùng final test."""
    import statistics
    import numpy as np
    from sklearn.utils.class_weight import compute_sample_weight
    labels = config["labels"]
    results = {name: [] for name in config["models"]}
    for index, fold in enumerate(folds, start=1):
        print(f"CV {group_name} fold {index}/{len(folds)} | train={len(fold['train'])} validation={len(fold['validation'])}", flush=True)
        x = prepare_features(fold, group)
        y = np.array([labels.index(r["ground_truth_label"]) for r in fold["train"]])
        weights = compute_sample_weight("balanced", y)
        truth = [r["ground_truth_label"] for r in fold["validation"]]
        for name, parameters in config["models"].items():
            model = make_model(name, parameters, 42, config["n_jobs"], len(labels))
            tick = perf_counter()
            model.fit(x["train"], y, sample_weight=weights)
            fit_seconds = perf_counter() - tick
            tick = perf_counter()
            prediction = model.predict(x["validation"])
            predict_seconds = perf_counter() - tick
            attack_scores = model.predict_proba(x["validation"])[:, list(model.classes_).index(labels.index("attack_behavior"))]
            scores = metrics(truth, [labels[int(i)] for i in prediction], labels, attack_scores)
            scores.update(fit_seconds=fit_seconds, predict_seconds=predict_seconds)
            results[name].append(scores)
            print(f"CV {name}: macro-F1={scores['macro_f1']:.4f}", flush=True)
    for name, scores in results.items():
        print(f"CV MEAN {group_name} {name}: accuracy={statistics.mean(s['accuracy'] for s in scores):.4f} "
              f"recall={statistics.mean(s['macro_recall'] for s in scores):.4f} "
              f"F1={statistics.mean(s['macro_f1'] for s in scores):.4f}", flush=True)
    return results


def train_models(splits, groups, config, output):
    import numpy as np
    from sklearn.utils.class_weight import compute_sample_weight
    labels = config["labels"]
    total_samples = sum(len(rows) for rows in splits.values())
    print(f"DATASET: tổng {total_samples:,} mẫu | {len(labels)} nhãn", flush=True)
    for split_name, rows in splits.items():
        sample_count = len(rows)
        label_counts = Counter(row["ground_truth_label"] for row in rows)
        run_ids = {row["run_id"] for row in rows if row.get("run_id")}
        print(f"  {split_name.upper()}: {sample_count:,} mẫu | {len(run_ids)} run thu thập", flush=True)
        for label in labels:
            count = label_counts[label]
            percentage = count / sample_count * 100 if sample_count else 0
            print(f"    {label}: {count:,} ({percentage:.2f}%)", flush=True)
    print(f"FEATURE GROUPS: {', '.join(groups)} | SEEDS: {config['seeds']} "
          f"| CV: {config.get('cv_splits', 0)} folds trên train", flush=True)
    for group_name, group in groups.items():
        numeric_count = len(group["numeric"])
        categorical_count = len(group["categorical"])
        print(f"  {group_name}: {numeric_count} feature số + {categorical_count} feature phân loại "
              "(trước preprocessing)", flush=True)
    print(f"MODELS: {', '.join(config['models'])}", flush=True)

    # XGBoost cần nhãn số 0..3. Chỉ đổi cách biểu diễn, không gộp nhãn.
    y = {split: np.array([labels.index(r["ground_truth_label"]) for r in rows])
         for split, rows in splits.items()}
    weights = compute_sample_weight("balanced", y["train"])
    folds = chronological_folds(splits["train"], labels, config["cv_splits"]) if config.get("cv_splits") else []
    results = []
    for group_name, group in groups.items():
        if folds:
            cross_validate_models(folds, group, group_name, config)
        print(f"PREPROCESS {group_name}: fit train only", flush=True)
        x = prepare_features(splits, group)
        for name, parameters in config["models"].items():
            for seed in config["seeds"]:
                print(f"TRAIN {group_name} | {name} | seed={seed} | {parameters}", flush=True)
                model = make_model(name, parameters, seed, config["n_jobs"], len(labels))
                started = perf_counter()
                model.fit(x["train"], y["train"], sample_weight=weights)
                fit_seconds = perf_counter() - started
                # Tham số cố định: validation chỉ kiểm tra, không dùng để chọn cấu hình.
                validation_prediction = [labels[int(i)] for i in model.predict(x["validation"])]
                validation_truth = [labels[int(i)] for i in y["validation"]]
                validation_score = metrics(validation_truth, validation_prediction, labels)["macro_f1"]
                tick = perf_counter()
                prediction = model.predict(x["test"])
                prediction_seconds = perf_counter() - tick
                predicted = [labels[int(i)] for i in prediction]
                truth = [labels[int(i)] for i in y["test"]]
                # AP dùng xác suất attack; giữ timer predict chỉ đo dự đoán nhãn.
                attack_scores = model.predict_proba(x["test"])[:, list(model.classes_).index(labels.index("attack_behavior"))]
                result = dict(feature_group=group_name, model=name, seed=seed,
                              parameters=parameters, validation_macro_f1=validation_score,
                              test=metrics(truth, predicted, labels, attack_scores),
                              fit_seconds=fit_seconds,
                              test_prediction_seconds=prediction_seconds)
                results.append(result)
                prefix = f"{group_name}_{name}_seed{seed}"
                # Chi tiết chỉ giữ trong RAM để tổng hợp; không xuất mỗi seed/session.
                print(f"DONE {prefix}: macro-F1={result['test']['macro_f1']:.4f}", flush=True)

    write_summary(results, groups, config["models"], output)
    return results


def export_random_forest_model(output_path=None):
    """Train and save the reported fused Random Forest with its preprocessing."""
    import joblib
    import numpy as np
    from sklearn.utils.class_weight import compute_sample_weight

    config = training_config()
    dataset_directory = DATASET_DIRECTORY
    output_path = output_path or ROOT / "src/models/random_forest_fused.joblib"

    print(f"DATASET PATH: {dataset_directory}", flush=True)
    print("AUDIT: checksum, privacy, labels, chronological split", flush=True)
    splits, dataset_report = load_data(dataset_directory, config)

    group = get_feature_groups()["C"]
    features, preprocessor = prepare_features(splits, group, return_preprocessor=True)
    train_labels = np.array([
        config["labels"].index(row["ground_truth_label"])
        for row in splits["train"]
    ])
    sample_weights = compute_sample_weight("balanced", train_labels)

    model = make_model(
        "random_forest",
        config["models"]["random_forest"],
        config["seeds"][0],
        config["n_jobs"],
        len(config["labels"]),
    )
    model.fit(features["train"], train_labels, sample_weight=sample_weights)

    bundle = {
        "format": "topic4-sklearn-model-v1",
        "model_name": "random_forest",
        "feature_group": "C",
        "labels": list(config["labels"]),
        "parameters": dict(config["models"]["random_forest"]),
        "seed": config["seeds"][0],
        "preprocessor": preprocessor,
        "model": model,
        "training_rows": len(splits["train"]),
        "dataset_report": dataset_report,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    print(f"MODEL SAVED: {output_path}", flush=True)
    return output_path


# Main Workflow
# -----------------------------------------------------------------------------
def run_baselines(group_names=None, train=False):
    config = training_config()
    if set(LABEL_NAMES) != LABELS or len(LABEL_NAMES) != len(LABELS):
        raise ValueError("Use exactly the four project labels")
    groups = get_feature_groups()
    selected = group_names or ["C"]
    groups = {name: groups[name] for name in dict.fromkeys(selected)}
    directory = DATASET_DIRECTORY
    if not (directory / "schema.json").is_file():
        raise ValueError(
            f"Thiếu dataset đã chuẩn bị tại {directory}. "
            "Chạy scripts/audit_custom_dataset.py, sau đó scripts/prepare_custom_ablation.py "
            "bằng Python của .venv trước khi train. Không xóa schema/splits/checksums của dataset.")
    print(f"DATASET PATH: {directory}", flush=True)
    print("AUDIT: checksum, privacy, labels, chronological split", flush=True)
    splits, _ = load_data(directory, config)
    if not train:
        print("PASS audit; không tạo thư mục hoặc file kết quả.", flush=True)
        return
    output = new_result_folder(OUTPUT_DIRECTORY)
    try:
        train_models(splits, groups, config, output)
    except BaseException:
        # Nếu lỗi trước khi có kết quả, bỏ thư mục rỗng vừa tạo.
        if not any(output.iterdir()):
            output.rmdir()
        raise
    print(f"PASS; output: {output}", flush=True)
