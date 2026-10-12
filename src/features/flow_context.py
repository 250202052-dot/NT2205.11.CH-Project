"""Feature L3/L4 tính từ metadata, không đọc payload hay thay dataset gốc.

Đầu vào: các dict từ sessions/labeled_sessions.csv.
Đầu ra: bản sao mỗi dict với một số feature bổ sung.
Window chỉ dùng session bắt đầu trước hoặc đúng thời điểm hiện tại.
Reset theo run_id để không nối traffic qua khoảng nghỉ giữa các round.
"""

from collections import defaultdict, deque
import math

FLOW_FEATURE_VERSION = "flow-context-v1"
DERIVED_FLOW_FIELDS = [
    "flow_total_bytes", "flow_total_packets", "flow_bytes_per_second",
    "flow_packets_per_second", "flow_src_byte_fraction",
    "flow_duration_missing_or_zero", "flow_source_connections_10s",
    "flow_source_connections_60s", "flow_source_unique_destinations_60s",
    "flow_source_unique_ports_60s",
]


def number(value):
    """Ô CSV trống -> None; không tự thay dữ liệu thiếu bằng số 0."""
    if value is None or value == "":
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("Flow numeric value must be finite and non-negative")
    return result


def total(left, right):
    """Nếu một phía chưa biết thì tổng cũng chưa biết."""
    left, right = number(left), number(right)
    return None if left is None or right is None else left + right


def enrich_flows(rows):
    """Tính trên tập quan sát được, trả về cùng thứ tự và không sửa rows.

    Timestamp/IP chỉ dùng tính cửa sổ; không tự trở thành input ML.
    Cửa sổ đếm cả session hiện tại. Đây là feature offline theo thời điểm
    bắt đầu; byte/duration chỉ biết đầy đủ khi session kết thúc.
    """
    output = [dict(row) for row in rows]
    # Mỗi nguồn trong mỗi round có một lịch sử riêng, không dùng ground truth.
    history = defaultdict(deque)
    ordered = sorted(enumerate(output), key=lambda item: (
        item[1]["run_id"], float(item[1]["timestamp_unix"]), item[1]["uid"]
    ))
    for _, row in ordered:
        ts = number(row["timestamp_unix"])
        if ts is None:
            raise ValueError("Flow context needs timestamp_unix")
        duration = number(row.get("duration_seconds"))
        byte_total = total(row.get("src_bytes"), row.get("dst_bytes"))
        packet_total = total(row.get("src_packets"), row.get("dst_packets"))
        row["flow_total_bytes"] = byte_total
        row["flow_total_packets"] = packet_total
        row["flow_duration_missing_or_zero"] = int(not duration)
        # Không chia cho 0, không tạo inf và không gán rate=0 cho dữ liệu thiếu.
        row["flow_bytes_per_second"] = byte_total / duration if duration and byte_total is not None else None
        row["flow_packets_per_second"] = packet_total / duration if duration and packet_total is not None else None
        row["flow_src_byte_fraction"] = number(row.get("src_bytes")) / byte_total if byte_total else None

        source_history = history[(row["run_id"], row["src_ip"])]
        while source_history and source_history[0][0] < ts - 60:
            source_history.popleft()
        source_history.append((ts, row["dst_ip"], str(row["dst_port"])))
        row["flow_source_connections_10s"] = sum(t >= ts - 10 for t, _, _ in source_history)
        row["flow_source_connections_60s"] = len(source_history)
        row["flow_source_unique_destinations_60s"] = len({dst for _, dst, _ in source_history})
        row["flow_source_unique_ports_60s"] = len({port for _, _, port in source_history})
    return output
