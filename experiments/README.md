# Các file thí nghiệm đang dùng

| File/thư mục | Vai trò |
|---|---|
| `campaign_attack_v3.json` | Quota và cách chạy campaign hiện tại |
| `custom_dataset_attack_v3.json` | Scenario và giới hạn traffic của attack v3 |
| `custom_dataset.json` | Generator cơ bản và fallback của campaign; code vẫn dùng |
| `lab_roles.json` | Mapping IP → role để join và gắn nhãn |
| `ablation_custom_config.json` | Cấu hình runner A/B/C trên subset hiện tại |
| `ablation_features_training_v2.json` | Feature A/B/C cho schema v2 |
| `requirements-*.txt` | Thư viện cần cho dataset, A/B/C và ba model |
| `datasets/custom_data_v1_ablation/` | Input train: CSV, schema, split, checksum; cần giữ |
| `results/dataset_audit/custom_data_v1/` | Audit dữ liệu; script prepare cần audit.json |
| `results/model_baselines/ketqua_lanN/summary.csv` | Kết quả so sánh ba model |

Baseline ba model chỉnh tham số trong `src/models/baselines.py`.
Runner A/B/C mặc định dùng chung tham số và feature trong source baseline.
Hai JSON A/B/C chỉ dành cho chế độ `--config` tương thích lệnh cũ.

Cấu hình lịch 20k/v2 và A/B/C đời đầu chuyển sang
`tests/fixtures/legacy_configs/` vì regression test vẫn cần chúng.
Không dùng các fixture đó để chạy campaign hiện tại.
