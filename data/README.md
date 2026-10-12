# Hướng dẫn thu custom dataset TLS/SSH

## Bổ sung vào dataset chính, không tạo campaign mới

```powershell
$env:ZEEK_EXTENDED_METADATA = 'true'
docker compose up -d --wait
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/custom_data_v1" --supplement --max-runs 1 --verbose
```

`--supplement` lập một block bổ sung ở cuối campaign. Chạy lại không lập trùng
block; tiếp tục phần chưa hoàn thành. Timestamp là giờ thu thật. Không đưa dữ
liệu thu sau test cũ vào train cũ. Các case mới gồm TLS beacon chậm/nhịp thay đổi,
TLS burst thay đổi, SSH guessing/spraying chậm, đường SSH thay đổi, proxy thay cert
trên cùng port 4443 và TLS policy regression. Có benign đối chứng trên cùng port,
cùng client: truy cập định kỳ/dồn đợt, SSH thử sai hai lần rồi đăng nhập đúng và
đường quản trị SSH hợp lệ. Chỉ là mô phỏng có kiểm soát, không chứng minh compromise,
C2 hoặc network downgrade thật. TLS policy regression vẫn là policy_violation.

Output công khai vẫn là `campaigns/custom_data_v1/dataset.csv` và
`scenario_manifest.csv`. Các round, bằng chứng và checkpoint cần cho resume/kiểm
tra giữ trong `.internal`. Chỉ round đã cleanup và validation thành công được
công bố; giữ các mẫu mới đã thu thật, không ép còn một mẫu theo quota tối thiểu.

Sau khi bổ sung và audit thành công, cập nhật lại input train tại cùng thư mục:

```powershell
.\.venv\Scripts\python.exe scripts/audit_custom_dataset.py
.\.venv\Scripts\python.exe scripts/prepare_custom_ablation.py --refresh
.\.venv\Scripts\python.exe scripts/check_dataset_quality.py
```

`--refresh` thay input đã chuẩn bị bằng bản mới ở cùng đường dẫn; kết quả model
cũ không tự cập nhật. Mẫu bổ sung muộn thuộc test, train/validation cũ giữ nguyên.

## Profile mới có thêm attack

Mặc định tạo campaign mới dùng attack v3 (8.000 attack / 20.000 session), có
quota từng nhóm hành vi và thời gian thực. Xem
[CUSTOM_DATASET_ATTACKS.md](../report/CUSTOM_DATASET_ATTACKS.md).
Resume campaign cũ giữ quota/profile cũ; không tự chuyển sang v3.

## Collection v2 không có ba khung giờ cố định

Hướng dẫn mới: [CUSTOM_DATASET_V2.md](../report/CUSTOM_DATASET_V2.md).
Muốn tạo riêng v2, truyền `--config experiments/campaign_flexible_v2.json`. `--max-runs 1` thu
một round rồi tự dừng; `--resume` tiếp tục lúc rảnh. Timestamp luôn là giờ thật.
Dataset training v2 nằm ở `campaigns/<id>/dataset/training/`; không chia sẻ
snapshot/local audit có IP lab. Hướng dẫn v1 bên dưới dành cho campaign cũ.

README này giải thích dữ liệu do lab tự tạo: lưu ở đâu, các file dùng làm gì và cách chạy lúc rảnh rồi tiếp tục hôm khác. Chạy các lệnh PowerShell bên dưới từ thư mục gốc `D:\NT2205.11.CH-Project`.

## 1. Hiểu ba phần chính

| Vị trí | Câu hỏi mà nó trả lời |
|---|---|
| `manifests/custom/<run_id>/` | Round này chủ động chạy hoạt động gì, vào lúc nào, nhãn đúng là gì? |
| `lab_metadata/custom/<run_id>/` | Zeek quan sát được gì và round này tạo được dataset nào? |
| `lab_metadata/campaigns/<campaign_id>/` | Cả campaign thu đến đâu và dataset tổng hợp nằm ở đâu? |

`custom` nghĩa là dữ liệu tự tạo trong lab. Hai thư mục có cùng `<run_id>` là một cặp kịch bản và kết quả. `public/` và `public_loaders/` dành cho dataset công khai; không phải output của campaign lab.

```text
Kịch bản có thời gian và nhãn (manifest)
                  +
Log metadata Zeek quan sát được
                  ↓
Ghép theo session, thời gian, nguồn/đích
                  ↓
Dataset có nhãn của từng round
                  ↓
Tổng hợp campaign, kiểm tra quota và chia tập
```

Một **round** là một lần chạy bộ sinh traffic rồi thu log và xử lý dữ liệu. Một **campaign** gồm nhiều round để đạt mục tiêu thu dữ liệu.

## 2. Cây thư mục

```text
data/
├── README.md
├── manifests/
│   └── custom/
│       └── <run_id>/
│           ├── scenario_manifest.csv
│           ├── background_http/scenario_manifest.csv
│           ├── background_db/scenario_manifest.csv
│           ├── background_ssh_outer/scenario_manifest.csv
│           ├── background_ssh_inner/scenario_manifest.csv
│           ├── background_tls_0/scenario_manifest.csv
│           └── <scenario_name>/scenario_manifest.csv
│
├── lab_metadata/
│   ├── zeek/                         # Log sensor đang ghi
│   ├── custom/
│   │   └── <run_id>/                  # Kết quả một round
│   │       ├── zeek/                 # Log được chọn cho round này
│   │       ├── sessions.csv
│   │       ├── labeled_sessions.csv
│   │       ├── labeled_sessions.parquet
│   │       ├── quarantined_sessions.csv
│   │       ├── quarantined_sessions.parquet
│   │       ├── dataset_summary.json
│   │       ├── generation_config.json
│   │       ├── background_events.json
│   │       ├── background_summary.json
│   │       ├── scenario_outcomes.json
│   │       ├── run_status.json
│   │       ├── schema.json
│   │       ├── privacy_validation.json
│   │       └── checksums.json
│   └── campaigns/
│       └── <campaign_id>/
│           ├── checkpoint.json
│           ├── .campaign.lock        # Khi campaign đang chạy
│           └── dataset/              # Khi bước tổng hợp chạy
│               ├── labeled_sessions.csv
│               ├── labeled_sessions.parquet
│               ├── campaign_summary.json
│               ├── schema.json
│               ├── privacy_validation.json
│               ├── run_provenance.json
│               ├── checksums.json
│               ├── full_collection/
│               ├── context/
│               └── splits/
│                   ├── train/
│                   ├── validation/
│                   └── test/
└── schemas/                          # Allowlist và validator
```

Đây là cấu trúc mẫu. Parquet chỉ có khi chạy với `--parquet`. Round benign-only không có thư mục abnormal. Thư mục tổng hợp chỉ xuất hiện khi bước aggregate chạy; các tập con chỉ được tạo khi có dữ liệu tương ứng.

## 3. Manifest: sổ ghi kịch bản

**File bạn cần xem là `manifests/custom/<run_id>/scenario_manifest.csv` ở ngoài cùng.** Pipeline dùng file tổng này để gán nhãn. Các file bên trong thư mục scenario chứa riêng từng mục để tra cứu.

| Cột | Ý nghĩa |
|---|---|
| `scenario_id` | Tên hoạt động, ví dụ `background_http`, `tls_expired_cert` |
| `start_time`, `end_time` | Thời gian thực bắt đầu/kết thúc, dạng Unix timestamp |
| `src_role`, `dst_role` | Vai trò máy nguồn và máy đích |
| `protocol`, `dst_port` | Giao thức và cổng đích |
| `expected_behavior` | Hành vi dự kiến |
| `expected_rule` | Rule dự kiến phát hiện; benign có thể để trống |
| `ground_truth_label` | Nhãn đúng theo kịch bản thử nghiệm |
| `scenario_type` | `background`, `abnormal` hoặc `benign_maintenance` |
| `completed` | Hoạt động đã hoàn thành hay chưa |

Ví dụ: thử certificate hết hạn trong một khoảng thời gian, từ client đến proxy, được ghi nhãn `misconfiguration`. Pipeline đối chiếu session Zeek với khoảng thời gian và nguồn/đích đó. Session không khớp chắc chắn được giữ riêng, không ép nhãn.

Các nhãn được phân biệt như sau:

| Nhãn | Ví dụ trong lab |
|---|---|
| `benign` | Truy cập hợp lệ, SSH được phép, gia hạn cert hợp lệ |
| `misconfiguration` | Cert hết hạn hoặc hostname không khớp |
| `policy_violation` | Thuật toán yếu hoặc đường SSH ngoài baseline |
| `attack_behavior` | Chuỗi kết nối xác thực thất bại kiểu brute-force-like |

Có cảnh báo Zeek không đồng nghĩa session là attack. Nhãn đến từ kịch bản đã kiểm soát, không lấy trực tiếp từ đầu ra detector.

## 4. Custom: kết quả từng round

| File | Dùng để làm gì? |
|---|---|
| `zeek/conn.log` | Metadata kết nối: IP, port, thời gian, byte, trạng thái |
| `zeek/ssl.log` | Metadata TLS handshake và thuật toán |
| `zeek/x509.log` | Metadata certificate khi sensor quan sát được |
| `zeek/ssh.log` | Metadata SSH và thuật toán thương lượng |
| `zeek/notice.log`, `weird.log` | Cảnh báo và bất thường của sensor |
| `sessions.csv` | Các log đã ghép thành session, trước bước gán nhãn |
| `labeled_sessions.csv/.parquet` | Session đã gán nhãn; hai định dạng của cùng dữ liệu |
| `quarantined_sessions.csv/.parquet` | Session chưa đủ điều kiện gán nhãn chắc chắn |
| `dataset_summary.json` | Thống kê kết quả xử lý của round |
| `generation_config.json` | Cấu hình thực tế dùng cho round |
| `background_events.json` | Chi tiết các lần thực hiện background |
| `background_summary.json` | Số lần thành công/thất bại của background |
| `scenario_outcomes.json` | Kết quả thực hiện từng scenario |
| `run_status.json` | Round hoàn thành và cleanup thành công chưa |
| `schema.json` | Các cột, kiểu dữ liệu và version |
| `privacy_validation.json` | Kết quả kiểm tra metadata-only |
| `checksums.json` | Mã kiểm tra file có bị thay đổi hay không |

Ví dụ tên round: `20261007T160605Z_campaign_646959_d1s0r5`.

- `20261007T160605Z_campaign_646959`: campaign ID; thời gian đầu tên dùng UTC.
- `d1`: ngày/block số 1.
- `s0`: slot đầu tiên.
- `r5`: round thứ 6 vì chỉ số round bắt đầu từ 0.

Nhiều thư mục xuất hiện vì mỗi round lưu kết quả riêng, không ghi đè round trước. Một session có thể xuất hiện ở log nguồn, bảng trung gian và bảng có nhãn; không cộng số dòng của mọi file để tính số session.

## 5. Campaign: tiến độ và dataset cuối

`checkpoint.json` lưu mode, cấu hình và danh sách round với trạng thái `pending`, `complete` hoặc `failed`. File này phục vụ `--resume`; tránh tự sửa trong lúc script chạy.

Trong `dataset/`:

| Vị trí | Ý nghĩa |
|---|---|
| `labeled_sessions.csv/.parquet` | Subset TLS/SSH đã chọn theo quota |
| `full_collection/` | Tất cả TLS/SSH có nhãn hợp lệ đã thu, kể cả phần vượt quota |
| `context/` | Flow HTTP/DB nội bộ; không tính vào mục tiêu 20.000 TLS/SSH |
| `splits/train/` | Ngày/block 1–3 |
| `splits/validation/` | Ngày/block 4 |
| `splits/test/` | Ngày/block 5 |
| `campaign_summary.json` | Số dòng, phân bố nhãn/giao thức, thiếu quota, độ đa dạng và ngày UTC thực tế |
| `run_provenance.json` | Tra ngược session về round, day/block và slot |

Output tổng hợp chỉ nhận round hoàn thành và cleanup thành công, kiểm tra checksum/privacy, rồi loại trùng theo `(run_id, uid)`. Dữ liệu quarantine vẫn nằm ở từng round.

## 6. Chạy lúc rảnh rồi tiếp tục hôm khác

### Bước 1: bật lab và xem trạng thái

```powershell
docker compose up -d
docker compose ps
```

Đợi các service healthy. Frontend và backend là container riêng; UI được truy cập qua proxy tại `https://localhost:8443`.

### Bước 2: xem cấu hình trước khi thu

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --config experiments/campaign_20k.json --mode compressed
```

Lệnh này chỉ preview, chưa tạo traffic. Nếu môi trường Python chưa có PyArrow, cài dependency trước khi xuất Parquet:

```powershell
.\.venv\Scripts\python.exe -m pip install -r experiments/requirements-dataset.txt
```

### Bước 3: bắt đầu campaign mới

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --config experiments/campaign_20k.json --mode compressed --collect --parquet
```

`compressed` chạy các block liên tiếp, không chờ 09:00/12:00/15:00. Timestamp vẫn là thời gian thực; 5 block không đồng nghĩa 5 ngày thực.

Tìm thư mục campaign vừa tạo dưới `data/lab_metadata/campaigns/` và ghi lại tên để tiếp tục lần sau.

### Bước 4: nghỉ

Nhấn `Ctrl+C` một lần, chờ script dọn dẹp và trả về dấu nhắc PowerShell rồi mới tắt máy. Round hoàn thành được giữ lại; round gián đoạn không được tính vào dataset cuối. Background chỉ chạy trong các round thu dữ liệu; không chạy khi máy đã tắt và có khoảng setup/flush/cleanup giữa các round.

### Bước 5: tiếp tục campaign cũ

Thay `TEN_CAMPAIGN` bên dưới bằng tên thư mục thực tế:

```powershell
docker compose up -d
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/TEN_CAMPAIGN" --parquet
```

Mode được đọc từ checkpoint. Chạy lại lệnh bước 3 sẽ tạo campaign mới; dùng `--resume` để tiếp tục đúng campaign cũ.

### Bước 6: tổng hợp dữ liệu đã có mà không sinh thêm traffic

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/TEN_CAMPAIGN" --aggregate-only --parquet
```

Lệnh này cần có ít nhất một round hoàn thành với TLS/SSH hợp lệ. Nếu chưa đủ quota, script vẫn giữ output thực tế và báo thiếu.

## 7. Khi nào script tự dừng?

Cấu hình mặc định có 5 ngày/block, mỗi ngày 3 slot. Mỗi slot ngừng tạo round mới khi đủ quota, đạt tối đa 18 round hoặc hết budget 90 phút. Round đang chạy được phép hoàn thành nên có thể vượt 90 phút một chút. Script chuyển sang slot tiếp theo, rồi tổng hợp và kết thúc khi xử lý hết campaign.

Mục tiêu là 20.000 session TLS/SSH duy nhất: benign 14.000, misconfiguration 2.000, policy_violation 3.000 và attack_behavior 1.000. Không đảm bảo đủ quota chỉ sau một lượt chạy; không nhân bản dòng để bù.

Nếu campaign compressed đã đạt giới hạn round nhưng còn thiếu, có thể tăng giới hạn thêm 6 round/slot khi resume:

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/TEN_CAMPAIGN" --extra-rounds 6 --parquet
```

Muốn thu theo ngày và giờ thực, dùng `--mode real --collect --parquet` khi tạo campaign mới. Mặc định bắt đầu ngày mai, chờ lịch 09:00/12:00/15:00; slot đã qua sẽ không được thu bù khi resume.

## 8. Chỉ cần xem những file nào?

| Bạn muốn biết | Mở file |
|---|---|
| Đang chạy tới đâu? | `campaigns/<campaign_id>/checkpoint.json` |
| Round này thử gì? | `manifests/custom/<run_id>/scenario_manifest.csv` ngoài cùng |
| Background có chạy thành công? | `custom/<run_id>/background_summary.json` trong lab_metadata |
| Round có hoàn thành? | `custom/<run_id>/run_status.json` trong lab_metadata |
| Dataset đã đủ 20.000 chưa? | `campaigns/<campaign_id>/dataset/campaign_summary.json` |
| Xem dữ liệu để phân tích? | `campaigns/<campaign_id>/dataset/labeled_sessions.csv` |

Trong `campaign_summary.json`, kiểm tra `selected_rows`, `quota_complete`, `shortfalls`, `class_counts`, `protocol_counts` và `actual_utc_dates`. Đủ số dòng chưa chứng minh đủ chất lượng; xem thêm độ đa dạng thời gian kết nối, TLS version, certificate và coverage scenario.

## 9. Giữ dữ liệu nhất quán và metadata-only

- Không xóa/sửa manifest hay output round khi campaign còn cần resume hoặc aggregate; checksum đang tham chiếu chúng.
- Không đổi TLS profile, build/recreate container hoặc chạy campaign thứ hai trong lúc đang thu. Dừng và đợi cleanup trước khi cập nhật lab.
- `.campaign.lock` và `.generation.lock` chặn chạy trùng. Nếu máy tắt đột ngột, lock và fixture có thể còn; xác nhận process cũ đã dừng và kiểm tra cleanup theo [CUSTOM_DATASET.md](../report/CUSTOM_DATASET.md) trước khi xử lý lock.
- Log `.log` là metadata JSON. Pipeline không lưu raw L7 payload, HTTP content, SSH username/command, credential, private key, decrypted TLS hoặc session secret.
- TLS 1.3 có thể không quan sát được certificate vì phần handshake đó được mã hóa; giữ field thiếu, không bịa dữ liệu.
- Khi huấn luyện, không đưa nhãn, scenario/run IDs hoặc đầu ra detector vào input để dự đoán chính nhãn đó.

Kiểm tra final dataset:

```powershell
.\.venv\Scripts\python.exe data/schemas/validate_zeek_metadata.py --dataset "data/lab_metadata/campaigns/TEN_CAMPAIGN/dataset"
```

## 10. File cấu hình và tài liệu liên quan

- [EXTENDED_METADATA.md](../report/EXTENDED_METADATA.md): bật profile thu IAT/packet size/TCP flags/TLS extension và kiểm tra bảng `extended/`.

- [ABLATION_STUDY.md](../report/ABLATION_STUDY.md): chuẩn bị feature và chạy A — L3/L4, B — TLS/SSH, C — Fused trên cùng dataset.

- [campaign_20k.json](../experiments/campaign_20k.json): quota, slot, budget và workload.
- [custom_dataset.json](../experiments/custom_dataset.json): cấu hình bộ sinh một round.
- [CAMPAIGN_20K.md](../report/CAMPAIGN_20K.md): hướng dẫn campaign và quality audit.
- [CUSTOM_DATASET.md](../report/CUSTOM_DATASET.md): chi tiết scenario, join và cleanup.
- [ZEEK_FEATURE_MAPPING.md](../report/ZEEK_FEATURE_MAPPING.md): nguồn các feature Zeek.
