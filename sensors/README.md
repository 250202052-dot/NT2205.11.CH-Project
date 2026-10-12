# Sensors

`zeek/local.zeek` là cấu hình đang được Compose mount read-only vào `/config`. Chỉ cho phép log conn/ssl/x509/ssh/notice/weird JSON theo field allowlist, không dump PCAP, không TLS decryption hay file extraction. TLS/SSH rules nằm cạnh local.zeek; package JA3/JA4/HASSH cài trong Dockerfile.

Hướng dẫn build, kiểm tra, trust pin và giới hạn quan sát: [ZEEK_METADATA.md](../report/ZEEK_METADATA.md). Nguồn gốc từng feature: [ZEEK_FEATURE_MAPPING.md](../report/ZEEK_FEATURE_MAPPING.md).

Image/entrypoint của sensor nằm ở `docker/zeek/`. `suricata/` mới là thư mục chờ, chưa triển khai hoặc thêm sensor.
