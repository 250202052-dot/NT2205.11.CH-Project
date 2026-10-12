
"""
CAMPAIGN MANAGER - TLS/SSH METADATA DATASET
==========================================

Chức năng:
1. Đọc và kiểm tra cấu hình campaign.
2. Tạo cấu hình thu thập dữ liệu TLS/SSH.
3. Chạy các round thu thập theo từng ngày và batch.
4. Theo dõi quota của từng loại dữ liệu.
5. Lưu checkpoint để có thể tiếp tục khi bị gián đoạn.
6. Tổng hợp và xuất dataset CSV/Parquet.

Lưu ý:
- Không trực tiếp thu thập nội dung ứng dụng Layer 7.
- Sử dụng generator và aggregate của project hiện tại.
- Không tự tạo dữ liệu giả để bù quota bị thiếu.
"""

# ============================================================
# 1. IMPORT LIBRARIES
# ============================================================

import argparse
import json
import os
import random
import re
import sys
import time
import uuid

from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# 2. PROJECT CONFIGURATION
# ============================================================

# ROOT là thư mục gốc của project.
# Script được đặt trong thư mục con, ví dụ scripts/.
ROOT = Path(__file__).resolve().parents[1]

# Cho phép Python import các module trong project.
sys.path.insert(0, str(ROOT))

from src.data_generation.generator import (
    generate,
    SCENARIOS,
    validate_config,
)

from src.features.aggregate_campaign import (
    aggregate,
    read_runs,
)


# Múi giờ được sử dụng cho toàn bộ campaign.
LOCAL_TZ = timezone(
    timedelta(hours=7),
    "Asia/Bangkok",
)


# Các nhãn dữ liệu cần thu thập.
DATA_LABELS = {
    "benign",
    "misconfiguration",
    "policy_violation",
    "attack_behavior",
}


# ============================================================
# 3. VALIDATION - KIỂM TRA DỮ LIỆU ĐẦU VÀO
# ============================================================

def validate_campaign_id(value):
    """
    Kiểm tra tên campaign có hợp lệ không.

    Ví dụ hợp lệ:
        campaign_001
        tls-ssh-test

    Không cho phép:
        ../folder
        test/folder
        CON
    """

    pattern = r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}"

    if not re.fullmatch(pattern, value):
        raise ValueError(
            "Campaign ID must contain 1..80 "
            "letters/digits/underscore/hyphen"
        )

    # Các tên thư mục Windows không cho phép sử dụng.
    reserved_names = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }

    if value.upper() in reserved_names:
        raise ValueError("Reserved Windows folder name")

    return value


def validate_day_targets(day):
    """
    Kiểm tra quota của một ngày.

    Mỗi ngày phải có đủ bốn loại dữ liệu:
    - benign
    - misconfiguration
    - policy_violation
    - attack_behavior
    """

    targets = day["targets"]

    if set(targets) != DATA_LABELS:
        raise ValueError("Missing class target")

    for quota in targets.values():
        if not isinstance(quota, int) or quota < 0:
            raise ValueError("Invalid quota")


def validate_attack_targets(day):
    """
    Kiểm tra quota cho từng attack family.

    Ví dụ:
        ssh_password_guessing: 10
        tls_beacon: 20

    Tổng quota attack family phải bằng quota attack_behavior.
    """

    attack_targets = day.get("attack_targets")

    if attack_targets is None:
        return

    for scenario_name, quota in attack_targets.items():

        # Kịch bản phải tồn tại.
        if scenario_name not in SCENARIOS:
            raise ValueError("Invalid attack family quota")

        # Kịch bản phải thuộc attack_behavior.
        scenario_label = SCENARIOS[scenario_name][1]

        if scenario_label != "attack_behavior":
            raise ValueError("Invalid attack family quota")

        # Quota phải là số nguyên không âm.
        if type(quota) is not int or quota < 0:
            raise ValueError("Invalid attack family quota")

    total_attacks = sum(attack_targets.values())

    if total_attacks != day["targets"]["attack_behavior"]:
        raise ValueError(
            "Attack family quotas must sum "
            "to attack_behavior target"
        )


def validate_slots(config):
    """
    Kiểm tra danh sách slot/batch.

    Campaign v1:
        09:00
        15:00

    Campaign v2:
        batch_1
        batch_2
    """

    slots = config["slots"]

    if not slots or len(set(slots)) != len(slots):
        raise ValueError("Slots must be unique and sorted")

    for slot in slots:

        if config["schema_version"] == "lab-campaign-v1":
            datetime.strptime(slot, "%H:%M")

        elif not re.fullmatch(r"batch_[0-9]+", slot):
            raise ValueError(
                "Flexible batches must be named "
                "batch_1, batch_2, ..."
            )


def validate_campaign(config):
    """
    Kiểm tra toàn bộ cấu hình campaign.

    Hàm này gọi những hàm validation nhỏ
    để tránh viết tất cả logic trong một hàm dài.
    """

    supported_versions = {
        "lab-campaign-v1",
        "lab-campaign-v2",
    }

    if (
        config.get("schema_version") not in supported_versions
        or config.get("timezone") != "Asia/Bangkok"
    ):
        raise ValueError("Unsupported campaign schema/timezone")

    # Ngày phải liên tiếp: 1, 2, 3...
    day_numbers = [
        day["day"]
        for day in config["days"]
    ]

    expected_days = list(range(1, len(day_numbers) + 1))

    if day_numbers != expected_days:
        raise ValueError(
            "Campaign days must be contiguous from 1"
        )

    # Kiểm tra từng ngày.
    for day in config["days"]:
        validate_day_targets(day)
        validate_attack_targets(day)

    # Kiểm tra giới hạn số round.
    max_rounds = config["max_rounds_per_slot"]
    budget = config["slot_budget_seconds"]

    if not (1 <= max_rounds <= 100):
        raise ValueError("Invalid collection budget")

    if not (10 <= budget <= 14400):
        raise ValueError("Invalid collection budget")

    validate_slots(config)

    if not config["workloads"]:
        raise ValueError("No workload profiles")

    # Giới hạn số kịch bản bất thường mỗi round.
    if "max_abnormal_scenarios_per_round" in config:

        cap = config["max_abnormal_scenarios_per_round"]

        if type(cap) is not int or not (1 <= cap <= len(SCENARIOS)):
            raise ValueError("Invalid abnormal scenario cap")

    # Kiểm tra khoảng nghỉ giữa các scenario.
    if "scenario_gap_seconds_range" in config:

        low, high = config["scenario_gap_seconds_range"]

        if not (0 <= low <= high <= 120):
            raise ValueError("Invalid scenario gap range")


# ============================================================
# 4. QUOTA MANAGEMENT
# ============================================================

def slot_targets(day, index, count):
    """
    Chia quota của một ngày cho các batch.

    Ví dụ:
        100 benign
        3 batch

    Kết quả:
        batch 1: 34
        batch 2: 33
        batch 3: 33

    Batch đầu nhận phần dư.
    """

    targets = {}

    for label, quota in day["targets"].items():

        base_quota = quota // count
        remainder = quota % count

        extra = 1 if index < remainder else 0

        targets[label] = base_quota + extra

    return targets


def get_slot_progress(records, include_context):
    """
    Đọc dữ liệu đã thu thập trong batch.

    Trả về:
        rows: danh sách session
        counts: số session theo từng nhãn
    """

    rows, _ = read_runs(
        records,
        include_context=include_context,
    )

    counts = Counter(
        row["ground_truth_label"]
        for row in rows
    )

    return rows, counts


def get_attack_family_counts(rows):
    """
    Đếm số lượng session của từng attack family.
    """

    return Counter(
        row["expected_behavior"]
        for row in rows
        if row["ground_truth_label"] == "attack_behavior"
    )


def calculate_remaining_quotas(day, quotas, rows, counts):
    """
    Tính quota còn thiếu của batch.

    Ví dụ:
        Target: 100 benign
        Collected: 70 benign
        Remaining: 30 benign

    Nếu có attack_targets, số attack còn thiếu
    được tính theo từng attack family.
    """

    remaining = {}

    for label, target in quotas.items():
        remaining[label] = max(
            0,
            target - counts[label],
        )

    family_quotas = day.get("attack_targets")
    remaining_families = None

    if family_quotas is not None:

        family_counts = get_attack_family_counts(rows)

        remaining_families = {}

        for name, target in family_quotas.items():
            remaining_families[name] = max(
                0,
                target - family_counts[name],
            )

        remaining["attack_behavior"] = sum(
            remaining_families.values()
        )

    return remaining, remaining_families


# ============================================================
# 5. RUN CONFIG GENERATION
# ============================================================

def load_generation_template(campaign):
    """
    Đọc cấu hình gốc của generator.

    Nếu campaign đã lưu generation_template:
        Sử dụng template đó.

    Nếu chưa có:
        Đọc từ file JSON.

    deepcopy bằng JSON giúp tránh sửa trực tiếp
    template đang được giữ trong campaign.
    """

    if "generation_template" in campaign:

        return json.loads(
            json.dumps(campaign["generation_template"])
        )

    config_path = ROOT / campaign.get(
        "generation_config",
        "experiments/custom_dataset.json",
    )

    return json.loads(
        config_path.read_text(encoding="utf-8")
    )


def select_workload(campaign, day, slot_index, round_index):
    """
    Chọn workload theo ngày, slot và round.

    Công thức được giữ nguyên để đảm bảo
    thứ tự workload không thay đổi.
    """

    workloads = campaign["workloads"]

    index = (
        day + slot_index + round_index
    ) % len(workloads)

    return workloads[index]


def apply_random_parameters(config, rng):
    """
    Sinh các tham số ngẫu nhiên cho một round.

    rng sử dụng seed cố định nên có thể
    tái lập các tham số khi chạy lại.

    Giữ nguyên thứ tự gọi rng để không làm
    thay đổi kết quả random so với code gốc.
    """

    config.update(
        seed=rng.randrange(1_000_000),
        diverse_workload=True,
        tls_versions=["1.2", "1.2", "1.3"],
        warmup_seconds=rng.uniform(60, 120),
        cooldown_seconds=rng.uniform(20, 45),
        window_seconds=rng.uniform(20, 50),
        gap_seconds=rng.uniform(2, 8),
        scenario_interval=rng.uniform(0.4, 1.8),
        brute_force_attempts=rng.randint(12, 30),
        brute_force_interval=rng.uniform(0.3, 1.0),
    )

    # Tham số cho profile có beacon/inventory.
    if config.get("collection_profile") in {
        "lab-v2",
        "lab-v3-attacks",
    }:

        config.update(
            beacon_interval=rng.uniform(1, 4),
            beacon_jitter=rng.uniform(0.05, 0.3),
            inventory_interval=rng.uniform(1, 3),
        )


def select_scenarios(
    campaign,
    config,
    day,
    remaining,
    remaining_families,
    rng,
    supplement,
):
    """
    Lựa chọn scenario cho round.

    Quy tắc:
    1. Ngày đầu tiên chỉ lấy benign baseline.
    2. Chọn scenario thuộc nhãn còn thiếu quota.
    3. Nếu có attack family quota thì lọc thêm.
    4. Xáo trộn scenario bằng RNG.
    5. Giới hạn abnormal scenario nếu cấu hình yêu cầu.
    """

    available = config["scenarios"]

    # Campaign v1 bổ sung scenario renewal.
    if campaign.get("schema_version") != "lab-campaign-v2":
        available = available + ["tls_benign_renewal"]

    # Ngày đầu chỉ chạy baseline.
    if day == 1:
        names = []
    else:
        names = [
            name
            for name in available
            if remaining[SCENARIOS[name][1]] > 0
        ]

    # Giới hạn attack family còn thiếu.
    if remaining_families is not None:

        names = [
            name
            for name in names
            if (
                SCENARIOS[name][1] != "attack_behavior"
                or remaining_families.get(name, 0) > 0
            )
        ]

    # Profile attack nâng cao.
    # Phải thực hiện trước rng.shuffle để giữ
    # nguyên chuỗi random ban đầu.
    if config.get("collection_profile") == "lab-v3-attacks":

        config.update(
            password_guess_interval=rng.uniform(0.4, 1),
            password_spray_interval=rng.uniform(1.5, 3),
            scan_repetitions=rng.randint(2, 4),
            scan_interval=rng.uniform(0.5, 2),
        )

    config["refresh_tls_fixtures"] = True

    rng.shuffle(names)

    # Giới hạn số lượng abnormal scenario.
    if (
        "max_abnormal_scenarios_per_round" in campaign
        and not supplement
    ):

        abnormal = [
            name
            for name in names
            if SCENARIOS[name][1] != "benign"
        ]

        cap = campaign["max_abnormal_scenarios_per_round"]

        keep = set(abnormal[:cap])

        names = [
            name
            for name in names
            if SCENARIOS[name][1] == "benign"
            or name in keep
        ]

    return names


def make_run_config(
    campaign,
    day,
    slot_index,
    round_index,
    remaining,
    remaining_families=None,
):
    """
    Tạo config hoàn chỉnh cho một round.

    Các bước:
    1. Load template.
    2. Kiểm tra supplement.
    3. Tạo RNG.
    4. Chọn workload.
    5. Sinh tham số random.
    6. Chọn scenario.
    7. Kiểm tra config.
    """

    config = load_generation_template(campaign)

    day_spec = next(
        (
            item
            for item in campaign["days"]
            if item["day"] == day
        ),
        {},
    )

    supplement = day_spec.get("supplement", False)

    if supplement:
        config["scenarios"] = list(
            day_spec["supplement_scenarios"]
        )

    # Seed riêng cho mỗi round.
    seed = (
        campaign["seed"]
        + day * 1000
        + slot_index * 100
        + round_index
    )

    rng = random.Random(seed)

    # Chọn workload.
    workload = select_workload(
        campaign,
        day,
        slot_index,
        round_index,
    )

    # Không copy field name vào generator config.
    config.update({
        key: value
        for key, value in workload.items()
        if key != "name"
    })

    apply_random_parameters(config, rng)

    names = select_scenarios(
        campaign,
        config,
        day,
        remaining,
        remaining_families,
        rng,
        supplement,
    )

    # Khoảng nghỉ giữa scenario.
    if "scenario_gap_seconds_range" in campaign:

        config["gap_seconds"] = rng.uniform(
            *campaign["scenario_gap_seconds_range"]
        )

    config.update(
        scenarios=names,
        benign_only=not names,
    )

    # Supplement sử dụng một số tham số riêng.
    if supplement:

        config.update(
            warmup_seconds=12,
            cooldown_seconds=10,
            gap_seconds=8,
            background_http_interval=3,
            background_ssh_interval=6,
            ssh_hold_ranges=[[0.2, 1], [1, 3]],
            tls_rate_limits=[0],
            password_attempts=6,
        )

    validate_config(config)

    return config


# ============================================================
# 6. SUPPLEMENT CAMPAIGN
# ============================================================

def plan_supplement(state, rounds):
    """
    Thêm block thu thập mới vào campaign hiện tại.

    Không thay đổi dữ liệu hoặc nhãn session cũ.
    """

    if (
        not state.get("simple_output")
        or state["mode"] != "flexible"
    ):
        raise ValueError(
            "Supplement needs a flexible campaign "
            "using simple-output"
        )

    if state.get("supplement_planned"):
        print(
            "Supplement already planned; "
            "resume unfinished supplement blocks.",
            flush=True,
        )
        return

    scenarios = [
        "tls_beacon_slow",
        "tls_beacon_variable",
        "tls_connection_burst_variable",
        "ssh_password_guessing_slow",
        "ssh_password_spraying_slow",
        "ssh_lateral_variable",
        "tls_interception_sameport",
        "tls_benign_periodic",
        "tls_benign_burst",
        "ssh_benign_password_retry",
        "ssh_benign_lateral_variable",
        "tls_policy_regression",
    ]

    first_day = len(state["config"]["days"]) + 1

    for index in range(rounds):

        attack_targets = {
            name: 1
            for name in scenarios
            if SCENARIOS[name][1] == "attack_behavior"
        }

        new_day = {
            "day": first_day + index,
            "supplement": True,
            "supplement_scenarios": scenarios,
            "retain_all_scenarios": True,
            "targets": {
                "benign": 600,
                "misconfiguration": 0,
                "policy_violation": 1,
                "attack_behavior": sum(
                    attack_targets.values()
                ),
            },
            "attack_targets": attack_targets,
        }

        state["config"]["days"].append(new_day)

    state["supplement_planned"] = True

    print(
        f"Supplement: {rounds} later block(s), "
        "actual timestamps; retain all validated new scenarios.",
        flush=True,
    )


# ============================================================
# 7. CHECKPOINT & RECOVERY
# ============================================================

def checkpoint(path, state):
    """
    Lưu trạng thái campaign vào checkpoint.json.

    Cách thực hiện:
    1. Ghi dữ liệu vào file .tmp.
    2. Thay thế checkpoint bằng file tạm.

    Giúp giảm nguy cơ checkpoint bị ghi dở.
    """

    temporary = path.with_suffix(".tmp")

    temporary.write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )

    temporary.replace(path)


def recover_pending_runs(records):
    """
    Khôi phục trạng thái những round còn pending.

    Nếu round trước đã hoàn thành và cleanup thành công:
        complete

    Ngược lại:
        failed
    """

    for record in records:

        if record["status"] != "pending":
            continue

        artifact = Path(record["artifact"])
        status_file = artifact / "run_status.json"

        if status_file.exists():
            recovered = json.loads(
                status_file.read_text()
            )
        else:
            recovered = {}

        is_complete = (
            recovered.get("completed")
            and recovered.get("cleanup_passed")
        )

        record["status"] = (
            "complete" if is_complete else "failed"
        )


# ============================================================
# 8. TIME MANAGEMENT
# ============================================================

def wait_until(when):
    """
    Chờ tới thời điểm thu thập trong real mode.

    Kiểm tra thời gian còn lại tối đa mỗi 30 giây.
    """

    while time.time() < when.timestamp():

        remaining = when.timestamp() - time.time()

        print(
            f"Waiting for {when.isoformat()}: "
            f"{int(remaining)} seconds",
            flush=True,
        )

        time.sleep(min(30, remaining))


def get_planned_time(base_date, day_number, slot):
    """
    Tính thời điểm bắt đầu của slot trong real mode.
    """

    hour, minute = map(int, slot.split(":"))

    current_date = base_date + timedelta(
        days=day_number - 1
    )

    planned = datetime.combine(
        current_date,
        datetime.min.time(),
        LOCAL_TZ,
    )

    return planned.replace(
        hour=hour,
        minute=minute,
    )


# ============================================================
# 9. SMOKE TEST CONFIG
# ============================================================

def apply_smoke_config(run_config):
    """
    Rút ngắn thời gian chạy để kiểm thử tích hợp.

    Chỉ dùng cho smoke test, không dùng làm
    dataset nghiên cứu chính thức.
    """

    run_config.update(
        warmup_seconds=4,
        cooldown_seconds=2,
        window_seconds=2,
        gap_seconds=0.5,
        scenario_interval=0.5,
        brute_force_attempts=6,
        brute_force_interval=0.3,
        ssh_hold_ranges=[[0.2, 0.5], [1, 2]],
        tls_rate_limits=[0],
        background_http_interval=0.5,
        background_ssh_interval=1,
    )

    if run_config.get("collection_profile") == "lab-v3-attacks":

        run_config.update(
            password_attempts=6,
            password_guess_interval=0.3,
            password_spray_interval=0.5,
            scan_repetitions=1,
            beacon_interval=0.5,
            tls_pattern_max_requests=6,
        )


# ============================================================
# 10. RUN RECORD MANAGEMENT
# ============================================================

def create_run_record(
    state,
    state_path,
    day_number,
    slot,
    slot_index,
    attempt,
    run_config,
):
    """
    Tạo thông tin quản lý một round.

    Trả về:
        run_id
        artifact
        record

    Record được lưu để hỗ trợ audit và resume.
    """

    run_id = (
        f"{state['campaign_id']}"
        f"_d{day_number}s{slot_index}r{attempt}"
    )

    if state.get("simple_output"):

        artifact = (
            state_path.parent
            / "rounds"
            / run_id
        )

        run_config["single_manifest"] = True

    else:

        artifact = (
            ROOT
            / "data/lab_metadata/custom"
            / run_id
        )

    record = {
        "run_id": run_id,
        "day": day_number,
        "slot": slot,
        "round": attempt,
        "artifact": str(artifact),
        "status": "pending",
        "actual_start_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    return run_id, artifact, record


def execute_run(
    state,
    state_path,
    record,
    run_config,
    artifact,
    parquet,
    smoke,
    verbose,
):
    """
    Thực thi một round thông qua generator.

    Nếu thành công:
        status = complete

    Nếu lỗi:
        status = failed
        checkpoint được cập nhật
        exception được đưa lên caller.
    """

    run_id = record["run_id"]

    extra = {}

    if state.get("simple_output"):
        extra["artifact_directory"] = artifact

    if verbose:
        extra["verbose"] = True

    try:

        generate(
            run_config,
            parquet=parquet,
            quick_sample=smoke,
            run_id=run_id,
            **extra,
        )

        record["status"] = "complete"

    except BaseException:

        record["status"] = "failed"
        checkpoint(state_path, state)

        raise

    checkpoint(state_path, state)

    record["actual_end_utc"] = datetime.now(
        timezone.utc
    ).isoformat()

    checkpoint(state_path, state)


# ============================================================
# 11. COLLECTION CONTROL
# ============================================================

def should_stop_collection(
    collected,
    max_runs,
    max_minutes,
    invocation_start,
):
    """
    Kiểm tra giới hạn của một lần chạy chương trình.

    Hai giới hạn:
        max_runs
        max_minutes

    Nếu đạt giới hạn thì không bắt đầu round mới.
    """

    if max_runs is not None and collected >= max_runs:
        return True

    if max_minutes is not None:

        elapsed = time.monotonic() - invocation_start

        if elapsed >= max_minutes * 60:
            return True

    return False


def check_flexible_batch_complete(
    day,
    quotas,
    records,
    config,
):
    """
    Kiểm tra batch flexible đã đủ quota chưa.

    Nếu chưa đủ:
        Dừng để người dùng resume sau.

    Điều này giúp giữ thứ tự thời gian của dataset.
    """

    include_context = (
        config.get("dataset_scope")
        == "all_labeled_sessions"
    )

    rows, counts = get_slot_progress(
        records,
        include_context,
    )

    # Kiểm tra quota theo nhãn.
    for label, target in quotas.items():

        if counts[label] < target:

            print(
                "Batch budget reached; "
                "resume this unfinished block later.",
                flush=True,
            )

            return False

    # Kiểm tra quota từng attack family.
    family_counts = get_attack_family_counts(rows)

    for name, target in day.get("attack_targets", {}).items():

        if family_counts[name] < target:

            print(
                "Attack family quota still incomplete; "
                "resume this block later.",
                flush=True,
            )

            return False

    return True


def collect(
    state,
    state_path,
    parquet=False,
    smoke=False,
    max_runs=None,
    max_minutes=None,
    on_round=None,
    verbose=False,
):
    """
    Hàm điều phối quá trình thu thập dữ liệu.

    Cấu trúc:
        Campaign
            -> Day
                -> Slot/Batch
                    -> Round
                        -> Generate
                        -> Checkpoint
                        -> Update quota

    Chỉ chuyển tới flexible batch tiếp theo
    khi batch hiện tại đã đủ quota.
    """

    config = state["config"]

    base_date = date.fromisoformat(
        state["start_date"]
    )

    invocation_start = time.monotonic()
    collected = 0

    include_context = (
        config.get("dataset_scope")
        == "all_labeled_sessions"
    )

    # Duyệt từng ngày.
    for day in config["days"]:

        day_number = day["day"]

        # Duyệt từng batch trong ngày.
        for slot_index, slot in enumerate(config["slots"]):

            end = None

            # Chế độ real: chờ thời điểm thực.
            if state["mode"] == "real":

                planned = get_planned_time(
                    base_date,
                    day_number,
                    slot,
                )

                end = planned + timedelta(
                    seconds=config["slot_budget_seconds"]
                )

                wait_until(planned)

                # Slot đã hết hạn thì bỏ qua.
                if datetime.now(LOCAL_TZ) >= end:
                    continue

            # Lấy những round đã có trong checkpoint.
            records = [
                record
                for record in state["runs"]
                if (
                    record["day"] == day_number
                    and record["slot"] == slot
                )
            ]

            recover_pending_runs(records)

            checkpoint(state_path, state)

            # Tính quota riêng của batch.
            quotas = slot_targets(
                day,
                slot_index,
                len(config["slots"]),
            )

            slot_started = time.monotonic()

            # Tiếp tục từ round chưa được chạy.
            for attempt in range(
                len(records),
                config["max_rounds_per_slot"],
            ):

                # Kiểm tra giới hạn của lần gọi hiện tại.
                if should_stop_collection(
                    collected,
                    max_runs,
                    max_minutes,
                    invocation_start,
                ):
                    return

                # Khôi phục record còn pending nếu
                # run_status.json đã tồn tại.
                for record in records:

                    path = Path(record["artifact"])

                    status_file = path / "run_status.json"

                    if (
                        record["status"] == "pending"
                        and status_file.exists()
                    ):

                        recovered = json.loads(
                            status_file.read_text()
                        )

                        is_complete = (
                            recovered.get("completed")
                            and recovered.get("cleanup_passed")
                        )

                        record["status"] = (
                            "complete"
                            if is_complete
                            else "failed"
                        )

                # Đọc kết quả đã thu thập.
                rows, counts = get_slot_progress(
                    records,
                    include_context,
                )

                # Tính quota chưa đạt.
                remaining, remaining_families = (
                    calculate_remaining_quotas(
                        day,
                        quotas,
                        rows,
                        counts,
                    )
                )

                # Đã đủ dữ liệu thì kết thúc batch.
                if not any(remaining.values()):
                    break

                # Kiểm tra budget của batch.
                elapsed = time.monotonic() - slot_started

                if elapsed >= config["slot_budget_seconds"]:
                    break

                # Real mode phải nằm trong thời gian slot.
                if (
                    state["mode"] == "real"
                    and datetime.now(LOCAL_TZ) >= end
                ):
                    break

                # Tạo cấu hình round.
                run_config = make_run_config(
                    config,
                    day_number,
                    slot_index,
                    attempt,
                    remaining,
                    remaining_families,
                )

                # Áp dụng smoke config nếu được yêu cầu.
                if smoke:
                    apply_smoke_config(run_config)

                # Tạo run record.
                run_id, artifact, record = create_run_record(
                    state,
                    state_path,
                    day_number,
                    slot,
                    slot_index,
                    attempt,
                    run_config,
                )

                # Lưu record trước khi chạy.
                state["runs"].append(record)
                records.append(record)

                checkpoint(state_path, state)

                print(
                    f"Collect block {day_number} "
                    f"batch {slot} round {attempt} "
                    f"at {record['actual_start_utc']}: "
                    f"remaining={remaining}",
                    flush=True,
                )

                if remaining_families:
                    print(
                        "Attack families remaining: "
                        f"{remaining_families}",
                        flush=True,
                    )

                # Thực thi generator.
                execute_run(
                    state,
                    state_path,
                    record,
                    run_config,
                    artifact,
                    parquet,
                    smoke,
                    verbose,
                )

                collected += 1

                # Callback cập nhật output sau round thành công.
                if on_round is not None:
                    on_round()

            # Flexible mode:
            # phải xử lý xong batch hiện tại trước.
            if state["mode"] == "flexible":

                is_complete = check_flexible_batch_complete(
                    day,
                    quotas,
                    records,
                    config,
                )

                if not is_complete:
                    return


# ============================================================
# 12. EXPORT DATASET
# ============================================================

def export_outputs(
    state,
    output,
    parquet=False,
    verbose=False,
):
    """
    Tổng hợp các round thành dataset hoàn chỉnh.

    Các công việc:
    1. Aggregate dữ liệu.
    2. Export training dataset.
    3. Tạo campaign summary.
    4. Tính checksum.
    5. Publish CSV nếu simple-output được bật.
    """

    if state.get("simple_output"):
        working = output / ".internal"
    else:
        working = output

    dataset = working / "dataset"

    if verbose:
        print(
            "EXPORT: aggregate successful rounds, "
            "compute features, validate privacy, update CSV",
            flush=True,
        )

    report = aggregate(
        state,
        dataset,
        parquet,
    )

    # Export nâng cao cho schema v2.
    if state["config"].get("schema_version") == "lab-campaign-v2":

        from src.features.training_dataset import export_campaign
        from src.features.label_sessions import checksum

        report["training_export"] = export_campaign(
            dataset,
            ROOT / ".local-secrets/dataset_hmac.key",
            parquet,
            simple_output=state.get("simple_output", False),
        )

        # Ghi báo cáo campaign.
        summary_file = dataset / "campaign_summary.json"

        summary_file.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        # Tạo checksum để kiểm tra tính toàn vẹn.
        checksums = {}

        for path in dataset.rglob("*"):

            if not path.is_file():
                continue

            if path.name == "checksums.json":
                continue

            relative_path = str(
                path.relative_to(dataset)
            )

            checksums[relative_path] = checksum(path)

        checksum_file = dataset / "checksums.json"

        checksum_file.write_text(
            json.dumps(checksums, indent=2),
            encoding="utf-8",
        )

        # Chế độ simple-output chỉ xuất các CSV công khai.
        if state.get("simple_output"):

            from src.data_generation.output import publish_csv

            publish_csv(
                state,
                output,
                dataset,
            )

            if verbose:

                print(
                    f"CSV UPDATED: {output / 'dataset.csv'} "
                    f"| rows={report['selected_rows']} "
                    f"| labels={report['class_counts']} "
                    f"| quota_complete={report['quota_complete']}",
                    flush=True,
                )

    return report


# ============================================================
# 13. COMMAND LINE ARGUMENTS
# ============================================================

def create_argument_parser():
    """
    Khai báo các tham số CLI.

    Ví dụ:
        --collect
        --resume
        --smoke
        --max-runs
        --simple-output
    """

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "experiments/campaign_attack_v3.json",
    )

    parser.add_argument(
        "--mode",
        choices=["flexible", "real", "compressed"],
        default=None,
    )

    parser.add_argument("--max-runs", type=int)

    parser.add_argument("--max-minutes", type=float)

    parser.add_argument("--start-date")

    parser.add_argument(
        "--collect",
        action="store_true",
    )

    parser.add_argument(
        "--resume",
        type=Path,
    )

    parser.add_argument("--campaign-id")

    parser.add_argument(
        "--aggregate-only",
        action="store_true",
    )

    parser.add_argument(
        "--parquet",
        action="store_true",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    parser.add_argument(
        "--simple-output",
        action="store_true",
    )

    parser.add_argument(
        "--smoke",
        action="store_true",
    )

    parser.add_argument(
        "--extra-rounds",
        type=int,
        default=0,
    )

    parser.add_argument(
        "--supplement",
        action="store_true",
    )

    parser.add_argument(
        "--supplement-blocks",
        type=int,
        default=1,
    )

    return parser


def validate_arguments(parser, args):
    """
    Kiểm tra các tham số CLI có mâu thuẫn không.
    """

    if args.supplement and (
        not args.resume
        or not 1 <= args.supplement_blocks <= 3
        or args.smoke
        or args.aggregate_only
    ):
        parser.error(
            "--supplement needs --resume, 1..3 blocks, "
            "and genuine collection (no smoke/aggregate-only)"
        )

    if args.simple_output and args.parquet:
        parser.error(
            "--simple-output exports CSV only; omit --parquet"
        )

    if (
        (args.max_runs is not None and args.max_runs < 1)
        or (
            args.max_minutes is not None
            and args.max_minutes <= 0
        )
    ):
        parser.error("Collection limits must be positive")

    if args.collect and args.aggregate_only:
        parser.error(
            "--collect and --aggregate-only cannot be used together"
        )

    generation_lock = (
        ROOT
        / "data/lab_metadata/custom/.generation.lock"
    )

    if (
        args.collect
        or (args.resume and not args.aggregate_only)
    ) and generation_lock.exists():

        parser.error(
            "Another generator is running/interrupted. "
            "Finish it or recover the lock before collection; "
            "no dataset changed."
        )

    if args.campaign_id:

        if args.resume:
            parser.error(
                "Use either --campaign-id for a new campaign "
                "or --resume for an existing one"
            )

        try:
            validate_campaign_id(args.campaign_id)

        except ValueError as error:
            parser.error(str(error))


# ============================================================
# 14. SMOKE CAMPAIGN SETUP
# ============================================================

def setup_smoke_campaign(config, args, parser):
    """
    Tạo campaign ngắn để kiểm thử pipeline.

    Giữ lại hai ngày:
    - Day 1: benign baseline
    - Day 2: abnormal scenarios
    """

    # Không áp dụng giới hạn abnormal scenario
    # của production trong smoke test.
    config.pop(
        "max_abnormal_scenarios_per_round",
        None,
    )

    if config["schema_version"] == "lab-campaign-v2":
        args.mode = "flexible"
    else:
        args.mode = "compressed"

    if args.mode == "flexible":
        slots = ["batch_1"]
    else:
        slots = ["09:00"]

    config.update(
        slots=slots,
        max_rounds_per_slot=1,
        slot_budget_seconds=300,
        days=[
            {
                "day": 1,
                "targets": {
                    "benign": 4,
                    "misconfiguration": 0,
                    "policy_violation": 0,
                    "attack_behavior": 0,
                },
            },
            {
                "day": 2,
                "targets": {
                    "benign": 4,
                    "misconfiguration": 3,
                    "policy_violation": 6,
                    "attack_behavior": 6,
                },
            },
        ],
    )

    if args.resume:
        parser.error(
            "--smoke creates a separate campaign; "
            "do not use it to resume research collection"
        )

    if config.get("attack_family_targets"):

        config["days"][0]["attack_targets"] = {}

        config["days"][1]["attack_targets"] = {
            name: 1
            for name in config["attack_family_targets"]
        }

        config["days"][1]["targets"]["attack_behavior"] = len(
            config["attack_family_targets"]
        )


# ============================================================
# 15. CREATE / RESUME CAMPAIGN
# ============================================================

def resume_campaign(args, parser, requested_mode):
    """
    Đọc checkpoint của campaign hiện có.

    Không tạo campaign mới.
    """

    output = args.resume.resolve()

    saved_checkpoint = (
        output / ".internal/checkpoint.json"
    )

    if not saved_checkpoint.exists():
        saved_checkpoint = output / "checkpoint.json"

    state = json.loads(
        saved_checkpoint.read_text()
    )

    if args.simple_output and not state.get("simple_output"):
        parser.error(
            "Use a new campaign for --simple-output; "
            "existing campaigns keep their layout"
        )

    if state.get("simple_output") and args.parquet:
        parser.error(
            "This campaign uses simple CSV output; "
            "omit --parquet"
        )

    if requested_mode:

        if (
            requested_mode == "real"
            and state["config"]["schema_version"] == "lab-campaign-v2"
        ):
            parser.error(
                "A flexible campaign cannot use scheduled real mode"
            )

        state["mode"] = requested_mode

    if not (0 <= args.extra_rounds <= 100):
        parser.error("extra-rounds must be 0..100")

    state["config"]["max_rounds_per_slot"] += (
        args.extra_rounds
    )

    validate_campaign(state["config"])

    return state, output


def create_new_campaign(config, args, parser):
    """
    Tạo một campaign hoàn toàn mới.

    Bao gồm:
    - Campaign ID
    - Start date
    - Generation template
    - Checkpoint state ban đầu
    """

    if args.campaign_id:

        campaign_id = args.campaign_id

    else:

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )

        campaign_id = (
            timestamp
            + "_campaign_"
            + uuid.uuid4().hex[:6]
        )

    output = (
        ROOT
        / "data/lab_metadata/campaigns"
        / campaign_id
    )

    if output.exists():
        parser.error(
            f"Campaign directory already exists; "
            f"use --resume: {output}"
        )

    output.mkdir(parents=True)

    # Ngày bắt đầu mặc định là ngày mai.
    first = args.start_date or (
        datetime.now(LOCAL_TZ).date()
        + timedelta(days=1)
    ).isoformat()

    date.fromisoformat(first)

    # Freeze generation template để đảm bảo
    # việc sửa JSON sau này không thay đổi campaign.
    if config.get("generation_config"):

        template_path = (
            ROOT / config["generation_config"]
        )

        config["generation_template"] = json.loads(
            template_path.read_text(encoding="utf-8")
        )

        validate_config(config["generation_template"])

        from src.features.label_sessions import checksum

        config["generation_template_sha256"] = checksum(
            template_path
        )

    state = {
        "campaign_id": campaign_id,
        "mode": args.mode,
        "start_date": first,
        "config": config,
        "runs": [],
        "simple_output": args.simple_output,
    }

    return state, output


# ============================================================
# 16. SUPPLEMENT VALIDATION
# ============================================================

def prepare_supplement(state, output, args, parser):
    """
    Kiểm tra campaign cũ đã hoàn thành trước khi
    thêm các supplement block mới.
    """

    summary_path = (
        output
        / ".internal/dataset/campaign_summary.json"
    )

    if not state.get("supplement_planned"):

        if (
            not summary_path.is_file()
            or not json.loads(
                summary_path.read_text()
            )["quota_complete"]
        ):
            parser.error(
                "Finish the existing campaign before "
                "planning later supplement blocks"
            )

    plan_supplement(
        state,
        args.supplement_blocks,
    )

    validate_campaign(state["config"])


# ============================================================
# 17. CAMPAIGN EXECUTION
# ============================================================

def execute_campaign(state, output, args):
    """
    Chạy toàn bộ campaign.

    Trình tự:
    1. Tạo checkpoint.
    2. Tạo lock file.
    3. Thu thập dữ liệu.
    4. Export dataset.
    5. Xóa lock file.

    Lock file giúp tránh hai tiến trình sử dụng
    cùng một campaign đồng thời.
    """

    if state.get("simple_output"):
        working = output / ".internal"
    else:
        working = output

    working.mkdir(
        parents=True,
        exist_ok=True,
    )

    state_path = working / "checkpoint.json"

    lock = output / ".campaign.lock"

    # Chế độ "x" sẽ báo lỗi nếu lock đã tồn tại.
    with lock.open("x") as handle:
        handle.write(str(os.getpid()))

    try:

        checkpoint(state_path, state)

        if not args.aggregate_only:

            # Simple output cập nhật CSV sau
            # mỗi round hoàn thành.
            if state.get("simple_output"):

                def publish():
                    export_outputs(
                        state,
                        output,
                        verbose=args.verbose,
                    )

            else:
                publish = None

            collect(
                state,
                state_path,
                parquet=args.parquet,
                smoke=args.smoke,
                max_runs=args.max_runs,
                max_minutes=args.max_minutes,
                on_round=publish,
                verbose=args.verbose,
            )

        # Tổng hợp kết quả cuối cùng.
        report = export_outputs(
            state,
            output,
            args.parquet,
            verbose=args.verbose,
        )

        print(
            json.dumps(report, indent=2)
        )

        print(
            f"Campaign: {output}",
            flush=True,
        )

        if not report["quota_complete"]:
            print(
                "Collection paused/short of quota. "
                "Resume the same folder later; "
                "no fabricated rows."
            )

    finally:

        # Luôn xóa lock khi thoát khỏi tiến trình.
        lock.unlink(missing_ok=True)


# ============================================================
# 18. MAIN FUNCTION
# ============================================================

def main():
    """
    Điểm bắt đầu chương trình.

    Hàm main chỉ giữ vai trò điều phối:
    - Đọc CLI
    - Validate
    - Tạo hoặc resume campaign
    - Execute

    Logic chi tiết nằm trong các hàm phía trên.
    """

    # Bước 1: Đọc tham số CLI.
    parser = create_argument_parser()
    args = parser.parse_args()

    # Bước 2: Validate CLI.
    validate_arguments(parser, args)

    # Bước 3: Đọc campaign config.
    config = json.loads(
        args.config.read_text(encoding="utf-8")
    )

    requested_mode = args.mode

    # Chọn mode mặc định.
    if args.mode is None:

        if config.get("schema_version") == "lab-campaign-v2":
            args.mode = "flexible"
        else:
            args.mode = "real"

    # Schema v2 không chạy real mode.
    if (
        config.get("schema_version") == "lab-campaign-v2"
        and args.mode == "real"
    ):
        parser.error(
            "v2 uses actual-time flexible collection; "
            "--mode real is for legacy schedules only"
        )

    # Bước 4: Cấu hình smoke test nếu cần.
    if args.smoke:
        setup_smoke_campaign(config, args, parser)

    # Bước 5: Kiểm tra campaign config.
    validate_campaign(config)

    if (
        args.simple_output
        and config["schema_version"] != "lab-campaign-v2"
        and not args.resume
    ):
        parser.error(
            "--simple-output requires a v2/v3 flexible campaign"
        )

    # Dry run: chỉ hiển thị kế hoạch.
    if not args.collect and not args.resume:

        if args.campaign_id:

            campaign_directory = str(
                ROOT
                / "data/lab_metadata/campaigns"
                / args.campaign_id
            )

        else:

            campaign_directory = (
                "Generated when collection starts"
            )

        plan = {
            "clock_mode": args.mode,
            "config": config,
            "dry_run": True,
            "simple_output": args.simple_output,
            "campaign_id": args.campaign_id,
            "campaign_directory": campaign_directory,
        }

        print(
            json.dumps(plan, indent=2)
        )

        return

    # Kiểm tra pyarrow nếu cần Parquet.
    if args.parquet:
        import pyarrow

    # Bước 6: Resume hoặc tạo campaign mới.
    if args.resume:

        state, output = resume_campaign(
            args,
            parser,
            requested_mode,
        )

    else:

        state, output = create_new_campaign(
            config,
            args,
            parser,
        )

    # Bước 7: Chuẩn bị supplement.
    if args.supplement:

        prepare_supplement(
            state,
            output,
            args,
            parser,
        )

    # Bước 8: Chạy campaign.
    execute_campaign(
        state,
        output,
        args,
    )


# ============================================================
# 19. PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
