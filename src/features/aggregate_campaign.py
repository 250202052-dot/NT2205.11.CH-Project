"""Aggregate validated runs; sample genuine TLS/SSH sessions without duplication."""
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import random

from src.features.label_sessions import write_tables, write_schema, checksum
from data.schemas.validate_zeek_metadata import validate_dataset


def read_runs(records, include_context=False):
    sessions, context, seen = [], [], {}
    for record in records:
        if record.get("status") != "complete":
            continue
        path = Path(record["artifact"])
        status = json.loads((path / "run_status.json").read_text())
        if not status.get("completed") or not status.get("cleanup_passed"):
            raise ValueError("Campaign contains an incomplete run")
        root = Path(__file__).resolve().parents[2]
        digests = json.loads((path / "checksums.json").read_text())
        for name, digest in digests.items():
            candidate = (path / name if len(Path(name).parts) == 1 else root / name).resolve()
            manifest_root = (root / "data/manifests/custom" / path.name).resolve()
            if not (candidate.is_relative_to(path.resolve()) or candidate.is_relative_to(manifest_root)):
                raise ValueError("Checksum path outside source artifact/manifest")
            if checksum(candidate) != digest:
                raise ValueError("Source checksum mismatch")
        validate_dataset(path)
        with (path / "labeled_sessions.csv").open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                key = (row["run_id"], row["uid"])
                if key in seen:
                    if seen[key] != row:
                        raise ValueError("Conflicting duplicate session")
                    continue
                seen[key] = dict(row)
                row["scenario_id"] = row["run_id"] + "_" + row["scenario_id"]
                (sessions if row["application_protocol"] in {"tls", "ssh"} else context).append(row)
    return (sessions + context if include_context else sessions), context


def select_balanced(rows, quota, provenance, seed):
    groups = defaultdict(list)
    for row in rows:
        run = provenance[row["run_id"]]
        groups[(run["slot"], row["application_protocol"], row["expected_behavior"])].append(row)
    rng = random.Random(seed)
    for group in groups.values():
        rng.shuffle(group)
    keys = sorted(groups)
    selected = []
    while keys and len(selected) < quota:
        next_keys = []
        for key in keys:
            if groups[key] and len(selected) < quota:
                selected.append(groups[key].pop())
            if groups[key]:
                next_keys.append(key)
        keys = next_keys
    return selected


def aggregate(state, output, parquet=False):
    output.mkdir(parents=True, exist_ok=True)
    records = state["runs"]
    all_rows, context = read_runs(records)
    if state["config"].get("dataset_scope") == "all_labeled_sessions":
        # Include controlled scan/burst sessions without a TLS/SSH handshake.
        # Do not silently discard L3/L4 scenarios from the class quotas.
        all_rows = all_rows + context
    provenance = {r["run_id"]: {k: r[k] for k in ("day", "slot", "round", "artifact")}
                  for r in records if r.get("status") == "complete"}
    selected, shortfalls = [], {}
    for target in state["config"]["days"]:
        for label, quota in target["targets"].items():
            pool = [r for r in all_rows if provenance[r["run_id"]]["day"] == target["day"] and r["ground_truth_label"] == label]
            if label == "attack_behavior" and "attack_targets" in target:
                # Enforce quotas per behavior, not only a combined attack count.
                for family, needed in target["attack_targets"].items():
                    family_pool = [r for r in pool if r["expected_behavior"] == family]
                    family_quota = max(needed, len(family_pool)) if target.get("retain_all_scenarios") else needed
                    chosen = select_balanced(family_pool, family_quota, provenance,
                                             state["config"]["seed"] + target["day"])
                    selected.extend(chosen)
                    if len(chosen) < needed:
                        shortfalls[f"day{target['day']}_attack_{family}"] = needed - len(chosen)
                continue
            # Không bỏ traffic bình thường chỉ để ép dataset đúng một tổng số.
            retain_surplus = target.get("retain_all_scenarios") or (label == "benign" and state["config"].get("retain_benign_surplus"))
            needed = max(quota, len(pool)) if retain_surplus else quota
            chosen = select_balanced(pool, needed, provenance, state["config"]["seed"] + target["day"])
            selected.extend(chosen)
            if len(chosen) < quota:
                shortfalls[f"day{target['day']}_{label}"] = quota - len(chosen)
    selected.sort(key=lambda row: (float(row["timestamp_unix"]), row["run_id"], row["uid"]))
    if not selected:
        raise ValueError("No validated TLS/SSH session available")
    write_tables(output, selected, [], parquet)
    write_schema(output)
    privacy = validate_dataset(output)
    (output / "privacy_validation.json").write_text(json.dumps(privacy, indent=2))
    (output / "run_provenance.json").write_text(json.dumps(provenance, indent=2))
    # Retain all collected TLS/SSH and internal context outside the training subset.
    for name, rows in (("full_collection", all_rows), ("context", context)):
        if rows:
            folder = output / name
            folder.mkdir(exist_ok=True)
            write_tables(folder, rows, [], parquet)
            write_schema(folder)
            validate_dataset(folder)
    splits = defaultdict(list)
    for row in selected:
        day = provenance[row["run_id"]]["day"]
        split = "train" if day <= 3 else "validation" if day == 4 else "test"
        splits[split].append(row)
    # Entire run and related ProxyJump/burst groups share the day-based split.
    for split, rows in splits.items():
        if state.get("simple_output"):
            continue
        folder = output / "splits" / split
        folder.mkdir(parents=True, exist_ok=True)
        write_tables(folder, rows, [], parquet)
        write_schema(folder)
        validate_dataset(folder)
    duration_bins = Counter()
    for row in selected:
        duration = float(row["duration_seconds"] or 0)
        duration_bins["lt1" if duration < 1 else "1to5" if duration < 5 else "5to30" if duration < 30 else "30to120" if duration < 120 else "ge120"] += 1
    coverage = Counter((provenance[r["run_id"]]["day"], provenance[r["run_id"]]["slot"], r["ground_truth_label"]) for r in selected)
    report = {"campaign_id": state["campaign_id"], "clock_mode": state["mode"], "timestamps_modified": False,
              "target_rows": sum(sum(d["targets"].values()) for d in state["config"]["days"]),
              "selected_rows": len(selected), "collected_tls_ssh": len(all_rows), "context_rows": len(context),
              "quota_complete": not shortfalls, "shortfalls": shortfalls,
              "class_counts": dict(Counter(r["ground_truth_label"] for r in selected)),
              "protocol_counts": dict(Counter(r["application_protocol"] for r in selected)),
              "day_slot_label_counts": {f"d{d}_{slot}_{label}": n for (d, slot, label), n in coverage.items()},
              "duration_bins_seconds": dict(duration_bins),
              "tls_certificate_missing": sum(r["application_protocol"] == "tls" and not r["cert_fingerprint"] for r in selected),
              "tls_version_counts": dict(Counter(r["tls_version"] or "missing" for r in selected if r["application_protocol"] == "tls")),
              "unique_cert_fingerprints": len({r["cert_fingerprint"] for r in all_rows if r["cert_fingerprint"]}),
              "actual_utc_dates": sorted({r["timestamp_utc"][:10] for r in selected}),
              "scenario_counts": dict(Counter(r["expected_behavior"] for r in selected)),
              "split_rows": {split: len(rows) for split, rows in splits.items()},
              "quality_note": "Quota completion is not proof of diversity/ML quality; review duration/coverage/availability audits.",
              "feature_version": selected[0]["feature_version"], "label_version": selected[0]["label_version"]}
    report["collection_scope"] = state["config"].get("dataset_scope", "tls_ssh_only")
    report["retain_benign_surplus"] = state["config"].get("retain_benign_surplus", False)
    report["class_percentages"] = {label: round(100 * n / len(selected), 3)
                                   for label, n in report["class_counts"].items()}
    report["attack_family_targets_by_block"] = {str(day["day"]): day["attack_targets"]
        for day in state["config"]["days"] if "attack_targets" in day}
    report["time_semantics"] = "Actual timestamps; day is an ordered quota block, slot is a batch label in flexible mode"
    # Join log mới theo run_id + uid, giữ các session cũ với presence=False.
    # Không thay feature baseline hoặc dùng packet metadata để suy ra nhãn.
    from src.features.extended_metadata import raw_indices, companion_rows, write_companion
    run_indices = {r["run_id"]: raw_indices(Path(r["artifact"]) / "zeek")
                   for r in records if r.get("status") == "complete"}
    if any(any(index.values()) for index in run_indices.values()):
        def extra_rows(rows):
            grouped = defaultdict(list)
            for row in rows:
                grouped[row["run_id"]].append(row)
            enriched = { (row["run_id"], row["uid"]): row
                         for run, group in grouped.items()
                         for row in companion_rows(group, run_indices[run]) }
            return [enriched[(row["run_id"], row["uid"])] for row in rows]
        report["extended_metadata"] = write_companion(output / "extended", extra_rows(selected), parquet)
        for name, rows in (("full_collection", all_rows), ("context", context)):
            if rows:
                write_companion(output / name / "extended", extra_rows(rows), parquet)
        for split, rows in splits.items():
            if not state.get("simple_output"):
                write_companion(output / "splits" / split / "extended", extra_rows(rows), parquet)
    (output / "campaign_summary.json").write_text(json.dumps(report, indent=2))
    digests = {str(p.relative_to(output)): checksum(p) for p in output.rglob("*") if p.is_file() and p.name != "checksums.json"}
    (output / "checksums.json").write_text(json.dumps(digests, indent=2))
    return report
