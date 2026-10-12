"""Xuất hai CSV dễ sử dụng; dữ liệu kiểm tra nằm trong .internal."""
import csv
import json
from pathlib import Path
import shutil

from src.data_generation.generator import MANIFEST_COLUMNS
from src.features.label_sessions import checksum
from data.schemas.validate_zeek_metadata import validate_dataset


def publish_csv(state, output, dataset):
    """Chỉ công bố round thành công, đã cleanup và vượt privacy validator.

    Ghi lại bản CSV tổng sau mỗi lần thu, không append mù gây trùng record
    khi resume. scenario_id có tiền tố run_id, khớp với dataset hiện có.
    """
    training = dataset / "training"
    validate_dataset(training)
    manifests = []
    for record in state["runs"]:
        if record["status"] != "complete":
            continue
        path = Path(record["artifact"])
        status = json.loads((path / "run_status.json").read_text())
        manifest = Path(status["manifest"]).resolve()
        if not manifest.is_relative_to(path.resolve()):
            raise ValueError("Simple-output manifest must belong to its run")
        with manifest.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                row["scenario_id"] = record["run_id"] + "_" + row["scenario_id"]
                manifests.append({"run_id": record["run_id"], **row})

    # Mỗi session được chọn phải truy ngược được đúng manifest và nhãn.
    mapping = {(r["run_id"], r["scenario_id"]): r["ground_truth_label"] for r in manifests}
    with (training / "labeled_sessions.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if mapping.get((row["run_id"], row["scenario_id"])) != row["ground_truth_label"]:
                raise ValueError("Dataset label does not match scenario manifest")

    temporary_manifest = output / "scenario_manifest.csv.tmp"
    with temporary_manifest.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id", *MANIFEST_COLUMNS])
        writer.writeheader()
        writer.writerows(manifests)
    temporary_data = output / "dataset.csv.tmp"
    shutil.copyfile(training / "labeled_sessions.csv", temporary_data)
    temporary_manifest.replace(output / "scenario_manifest.csv")
    temporary_data.replace(output / "dataset.csv")
    # Schema/checksum vẫn được giữ để có thể kiểm tra dataset về sau.
    (output / ".internal/public_checksums.json").write_text(json.dumps({
        name: checksum(output / name) for name in ("dataset.csv", "scenario_manifest.csv")
    }, indent=2), encoding="utf-8")
