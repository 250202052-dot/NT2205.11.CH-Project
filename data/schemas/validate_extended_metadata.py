"""Kiểm tra metadata packet/TLS mở rộng; không chấp nhận raw strings/payload.

Tái sử dụng ở validator log và exporter bảng bổ sung. Đơn vị IAT: giây;
std: population standard deviation. Vector packet giới hạn tối đa 128.
"""

import math

PACKET_FIELDS = ["sequence_limit", "orig_observed_packets", "resp_observed_packets", "orig_iat_count", "resp_iat_count",
                 "orig_iat_mean", "orig_iat_std", "resp_iat_mean", "resp_iat_std", "unordered_timestamps",
                 "pkt_size_vector", "pkt_direction_vector", "sequence_truncated", "tcp_flags_orig", "tcp_flags_resp"]
TLS_FIELDS = ["client_hello_observed", "server_hello_observed", "client_extensions", "server_extensions",
              "ech_observed", "client_signature_schemes", "server_signature_scheme"]


def integer(value, maximum=None):
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError("Invalid bounded metadata integer")


def vector(value, maximum, length_limit):
    if not isinstance(value, list) or len(value) > length_limit:
        raise ValueError("Invalid metadata vector length")
    for item in value:
        integer(item, maximum)


def validate_record(stream, record):
    """Field allowlist được validator chính kiểm tra trước khi gọi hàm này."""
    if not isinstance(record.get("uid"), str) or not record["uid"] or len(record["uid"]) > 128:
        raise ValueError("Missing/invalid extended metadata UID")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in record["uid"]):
        raise ValueError("Invalid UID token")
    if isinstance(record.get("ts"), bool) or not isinstance(record.get("ts"), (int, float)) or not math.isfinite(record["ts"]):
        raise ValueError("Invalid extended metadata timestamp")
    version = "packet-metadata-v1" if stream == "packet_metadata" else "tls-extensions-v1"
    if record.get("metadata_version") != version:
        raise ValueError("Invalid extended metadata version")
    if stream == "packet_metadata":
        for field in ("sequence_limit", "orig_observed_packets", "resp_observed_packets", "orig_iat_count", "resp_iat_count", "unordered_timestamps"):
            integer(record.get(field))
        limit = record["sequence_limit"]
        if not 1 <= limit <= 128:
            raise ValueError("Packet sequence limit must be 1..128")
        total = record["orig_observed_packets"] + record["resp_observed_packets"]
        vector(record.get("pkt_size_vector"), 65575, limit)
        vector(record.get("pkt_direction_vector"), 1, limit)
        if len(record["pkt_size_vector"]) != min(total, limit) or len(record["pkt_direction_vector"]) != len(record["pkt_size_vector"]):
            raise ValueError("Packet sequence/count mismatch")
        if type(record.get("sequence_truncated")) is not bool or record["sequence_truncated"] != (total > limit):
            raise ValueError("Invalid packet truncation status")
        for side in ("orig", "resp"):
            packets, count = record[f"{side}_observed_packets"], record[f"{side}_iat_count"]
            if count > max(0, packets - 1):
                raise ValueError("Invalid IAT interval count")
            for suffix in ("mean", "std"):
                value = record.get(f"{side}_iat_{suffix}")
                if count and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                    raise ValueError("Invalid IAT statistic")
                if not count and value is not None:
                    raise ValueError("IAT must be missing without intervals")
            if f"tcp_flags_{side}" in record:
                flags = record[f"tcp_flags_{side}"]
                vector(flags, packets, 8)
                if len(flags) != 8:
                    raise ValueError("TCP flags must have exactly eight counters")
    else:
        for field in ("client_hello_observed", "server_hello_observed", "ech_observed"):
            if field in record and type(record[field]) is not bool:
                raise ValueError("Invalid TLS observation flag")
        for field in ("client_hello_observed", "server_hello_observed", "client_extensions", "server_extensions"):
            if field not in record:
                raise ValueError("Missing TLS extension metadata")
        for field in ("client_extensions", "server_extensions", "client_signature_schemes"):
            if field in record:
                vector(record[field], 65535, 1024)
        if "server_signature_scheme" in record:
            integer(record["server_signature_scheme"], 65535)
        if record["client_hello_observed"]:
            if record.get("ech_observed") != (65037 in record["client_extensions"]):
                raise ValueError("ECH presence inconsistent with ClientHello")
        elif "ech_observed" in record:
            raise ValueError("ECH must be unknown without ClientHello")
