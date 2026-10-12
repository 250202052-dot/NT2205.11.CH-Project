"""Chạy A/B/C trên cùng dataset và split, không thay dữ liệu thu gốc.

Mặc định chỉ audit (kiểm tra); thêm --train mới huấn luyện.
Đọc report/CUSTOM_DATASET_AUDIT_ABLATION.md trước khi chạy lần đầu.
"""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.models.ablation import feature_groups, load_data, read_csv, run_ablation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Optional legacy config; defaults use baseline source parameters")
    parser.add_argument("--dataset", type=Path, help="Override dataset directory")
    parser.add_argument("--train", action="store_true", help="Train models after mandatory audit")
    args = parser.parse_args()
    run_ablation(dataset=args.dataset, train_models=args.train, config_path=args.config)



if __name__ == "__main__":
    # Đặt UTF-8 để --help và thông báo lỗi không bị lỗi charmap.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        main()
    except (OSError, ValueError, ImportError) as error:
        raise SystemExit(f"FAIL: {error}")
