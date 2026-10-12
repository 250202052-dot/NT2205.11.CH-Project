# Cấu trúc thư mục project

Root là `D:\NT2205.11.CH-Project`, không tạo thêm thư mục lồng `project-root`.

```text
project-root/
├── compose.yaml
├── .env.example
├── README.md
├── data/
│   ├── public_loaders/            # Code loader NF-UQ/IoT-23/CESNET/CTU, chưa có
│   ├── public/                    # Dataset công khai tải về, giữ local
│   ├── lab_metadata/
│   │   ├── zeek/                  # conn/ssl/x509/ssh JSON; edge/internal là log cũ
│   │   └── sessions.csv           # Snapshot ghép metadata, chưa gắn attack labels
│   ├── manifests/                 # Thời gian, điều kiện/ground truth scenario
│   └── schemas/                   # Allowlist + privacy validator, chưa triển khai
├── sensors/
│   ├── zeek/local.zeek            # Config Zeek đang dùng
│   └── suricata/                  # Chờ triển khai nếu cần, chưa chạy container
├── src/
│   ├── data_generation/           # generator/runtime/scenarios/attacks/output
│   ├── features/build_sessions.py
│   ├── models/                    # baselines.py + ablation.py: model/train/metrics
│   ├── hunting/                   # Chờ evidence graph + ATT&CK retrieval
│   ├── agent/                     # Chờ policy guard/planner/verifier
│   └── response/                  # Chờ simulator/bounded lab adapters
├── experiments/                  # Config hiện tại, input train và kết quả
├── tests/
│   ├── test_lab.ps1               # TLS/SSH/ACL/mirror/metadata integration
│   ├── test_shop.py               # Đơn hàng, giá, tồn kho, gửi lặp
│   └── test_tls_profiles.py       # 6 profiles + strict client + Zeek/manifest
├── docker/
│   ├── router/                    # Alpine NAT/forwarding/ACL/mirror
│   ├── web/                       # Frontend/backend/DB fixture cho lab
│   │   ├── Dockerfile             # Ba build targets
│   │   ├── frontend/              # HTML/CSS/JS + Nginx
│   │   ├── backend/               # Shop API Python
│   │   ├── db/                    # PostgreSQL config
│   │   └── common/                # Bootstrap/network/SSH/supervisor
│   ├── proxy/                     # TLS config, certificate generator
│   ├── bastion/                   # Init script cho image LinuxServer
│   ├── client/                    # Client test tạm
│   └── zeek/                      # Dockerfile + entrypoint sensor
├── scripts/
│   ├── start-lab.ps1              # Khởi tạo keys và start lab
│   ├── trust-lab-hosts.ps1         # Cấp known_hosts cho client
│   ├── run_dataset_campaign.py    # Thu/resume campaign
│   ├── audit_custom_dataset.py    # Audit và privacy
│   ├── prepare_custom_ablation.py # Chuẩn bị input train
│   ├── run_model_baselines.py     # RF/XGBoost/LightGBM
│   ├── run_ablation.py            # A/B/C Random Forest riêng
│   └── dataset_tools.py           # Export thủ công training/extended
└── report/
    ├── TOPOLOGY.md
    ├── TLS_PROFILES.md
    ├── README_PLAN.md
    └── STRUCTURE.md
```

## Các phần đã chuyển

| Trước | Sau |
| --- | --- |
| `lab/<component>/` | `docker/<component>/` |
| `zeek/local.zeek` | `sensors/zeek/local.zeek` |
| `zeek/Dockerfile`, `zeek/entrypoint.sh` | `docker/zeek/` |
| `scripts/build_sessions.py` | `src/features/build_sessions.py` |
| `test-lab.ps1` | `tests/test_lab.ps1` |
| `scripts/test_shop.py`, `scripts/test_tls_profiles.py` | `tests/` |
| `logs/` | `data/lab_metadata/zeek/` |
| `data/sessions.csv` | `data/lab_metadata/sessions.csv` |
| `data/pub_dataset/` | `data/public/` |
| `TOPOLOGY.md`, `TLS_PROFILES.md`, `README_PLAN.md` | `report/` |

Shop API đặt trong `docker/web/backend` vì là ứng dụng sinh traffic thử nghiệm. `src/` dành cho pipeline phân tích metadata của đề tài. Volume PostgreSQL, SSH keys và certs vẫn do Docker quản lý, không đưa secrets vào source/dataset.

## Các lệnh hiện tại

Chạy từ root trong PowerShell:

```powershell
cd D:\NT2205.11.CH-Project
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\test_lab.ps1
python tests/test_shop.py
python tests/test_tls_profiles.py
python src/features/build_sessions.py
```

Chạy các integration tests lần lượt vì chúng thay profile/restart sensor hoặc tạo đơn thử. Test shop cần profile modern và tạo một đơn; test TLS tạo manifest, khôi phục profile ban đầu và gỡ client nếu do nó tạo.

Đọc dataset snapshot tại `data/lab_metadata/sessions.csv`. `--logs`/`--output` của build_sessions vẫn cho phép chọn đường dẫn khác. Trong container Zeek, log vẫn ở `/logs`; Compose bind thư mục mới trên host vào đường dẫn này.

Các thư mục trống có `.gitkeep` để Git giữ cấu trúc. Tạo thư mục không đồng nghĩa validator/models/agent đã hoạt động. Code public loaders có thể commit; dataset công khai, generated logs/CSV/manifests và secrets được loại khỏi Git.
