"""Công cụ phụ cho dataset đã thu: export training hoặc extended metadata.

Thu campaign và train thường ngày không cần chạy file này.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.features.extended_metadata import export_run, validate_companion
from src.features.training_dataset import export_campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    training = commands.add_parser("training", help="Export training từ campaign dataset")
    training.add_argument("--dataset", type=Path, required=True)
    training.add_argument("--parquet", action="store_true")
    extended = commands.add_parser("extended", help="Export hoặc validate extended metadata")
    choice = extended.add_mutually_exclusive_group(required=True)
    choice.add_argument("--run", type=Path)
    choice.add_argument("--validate", type=Path)
    extended.add_argument("--parquet", action="store_true")
    args = parser.parse_args()
    if args.command == "training":
        result = export_campaign(args.dataset, ROOT / ".local-secrets/dataset_hmac.key", args.parquet)
    elif args.run:
        result = export_run(args.run, args.parquet)
    else:
        result = validate_companion(args.validate)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"FAIL: {error}")
