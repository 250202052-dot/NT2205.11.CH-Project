"""Lệnh chạy baseline; code và tham số nằm trong src/models/baselines.py."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.models.baselines import export_random_forest_model, run_baselines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--groups", nargs="+", choices=["A", "B", "C"], help="Mặc định C = Fused")
    parser.add_argument("--train", action="store_true", help="Huấn luyện sau khi kiểm tra dữ liệu")
    parser.add_argument("--export-rf", action="store_true", help="Export fused Random Forest and preprocessing")
    args = parser.parse_args()
    if args.export_rf:
        export_random_forest_model()
    else:
        run_baselines(group_names=args.groups, train=args.train)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        main()
    except (OSError, ValueError, ImportError) as error:
        raise SystemExit(f"FAIL: {error}")
