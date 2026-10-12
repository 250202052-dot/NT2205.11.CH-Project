# Custom lab dataset: nền benign chiếm đa số, attack có kiểm soát

## 1. Mục tiêu và phạm vi

Bám mục 6 và 13.3 của Word: encrypted TLS beacon, SSH brute-force/spraying,
SSH new path/lateral sequence, TLS interception fixture, L3/L4 scan/burst.
Chạy traffic thật bằng **OpenSSH, Nmap, curl và Nginx** trong topology hiện có.
Không cần malware/C2 framework thật để đáp ứng hướng dẫn tạo fixture trong Word.

Giữ collection linh hoạt: không hẹn giờ, timestamp thật, resume lúc rảnh.
Normal HTTP/DB/SSH/TLS tiếp tục trong mỗi phiên thu. Không thêm container
thường trực. Bộ thu vẫn join Zeek `conn/ssl/x509/ssh/notice` và companion
metadata bằng pipeline hiện có.

Đây là dataset thử nghiệm có ground truth từ hoạt động lab được lên kế hoạch.
Không khẳng định một connection tự nó chứng minh có compromise hay malware.

## 2. Quota mới

| Nhãn | Số session trong subset cuối | Tỷ lệ |
|---|---:|---:|
| benign | Ít nhất 27.000 | khoảng 90% |
| misconfiguration | 900 | khoảng 3% |
| policy_violation | 900 | khoảng 3% |
| attack_behavior | 1.200 | khoảng 4% |
| Tổng mục tiêu tối thiểu | 30.000 | 100% khi chưa tính benign dư |

Block 1: ít nhất 6.000 benign. Block 2–5: mỗi block ít nhất 5.250 benign,
225 misconfiguration, 225 policy_violation và 300 attack_behavior.
Không ép tổng đúng 20.000: giữ toàn bộ session benign hợp lệ của các round đã
hoàn tất; nhóm bất thường vẫn chọn theo quota từng hành vi, không nhân bản/pad.
Vì benign có thể dư, tổng có thể vượt 30.000 và tỷ lệ attack có thể thấp hơn 4%.
Summary ghi `class_counts`, `class_percentages`, `selected_rows`, `quota_complete`.
Đây là tỷ lệ thiết kế cho lab, **không phải tỷ lệ attack đo được trong mạng thực tế**.
Tỷ lệ thật tùy môi trường, khoảng thời gian và đơn vị đếm (session/event/window).

Mỗi round chèn tối đa hai case bất thường, chọn ngẫu nhiên trong các nhóm còn
thiếu quota. Giữa các scenario nghỉ 20–60 giây, background vẫn hoạt động. Khi
đủ quota một nhóm thì không tiếp tục chèn nhóm đó. Smoke riêng vẫn chạy đủ case.
Baseline block đầu chỉ có benign; các block sau vẫn giữ mọi nhóm để train,
validation và test có thể đo recall. Quota đủ chưa chứng minh số mẫu đủ cho DL.

Tham khảo cách [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
ưu tiên background hợp lý và chèn attack theo thời gian; nguồn này không quy
định tỷ lệ 90/3/3/4. Muốn đánh giá triển khai thật cần traffic và prevalence
thực tế riêng, thay vì coi lab là đại diện của doanh nghiệp.
Toàn bộ session đã thu vẫn ở `full_collection/` (trong `.internal` nếu output gọn).

### Quota attack theo hành vi

| Scenario | Mỗi block 2–5 | Tổng | Thực hiện |
|---|---:|---:|---|
| `ssh_password_guessing` | 45 | 180 | Nhiều candidate sai vào một tài khoản lab |
| `ssh_password_spraying` | 30 | 120 | Một candidate sai cho ba tài khoản lab, lặp theo vòng |
| `tls_beacon_jitter` | 40 | 160 | HTTPS định kỳ với jitter 50–150% quanh interval |
| `tls_beacon_burst` | 35 | 140 | Nhóm 3 HTTPS connection, rồi nghỉ |
| `tls_connection_burst` | 30 | 120 | Tối đa 2 request đồng thời, burst hữu hạn |
| `nmap_tcp_connect_scan` | 40 | 160 | TCP connect vào port mở và đóng của proxy |
| `nmap_ssh_horizontal_scan` | 30 | 120 | Discovery port SSH trên backend và DB |
| `ssh_lateral_sequence` | 30 | 120 | ProxyJump bằng key lab đến backend rồi DB |
| `tls_interception_fixture` | 20 | 80 | Client → TLS proxy CA riêng → TLS upstream |

Đủ tổng attack nhưng thiếu một nhóm vẫn chưa đạt quota. Script chỉ tiếp tục
những nhóm còn thiếu, giúp attack data không bị một case chiếm hết.

## 3. Công cụ và bằng chứng

### SSH password guessing/spraying

OpenSSH client thực sự yêu cầu password authentication trên **listener tạm
2223**, không đổi bastion quản trị 2222. Server tạo bốn tài khoản lab tạm với
password ngẫu nhiên mạnh. Client chỉ thử candidate sai, không dùng wordlist
thật hay tài khoản thật. Giới hạn 6–30 attempts/scenario; mỗi connection chỉ
gửi một password candidate.

SSH askpass đọc candidate từ file tạm trong client. Không truyền password qua
command argv, không ghi password/username vào manifest, Zeek hay final dataset.
Auth logging fixture tắt. Cleanup xóa tài khoản, file candidate, helper và
listener. `scenario_outcomes.json` chỉ lưu attempt/failure count, số tài khoản
lab và completed status.

Chỉ exit 255 cùng password rejection đúng kỳ vọng mới được tính là failed
authentication. Timeout/host-key error không được coi là attack đã thực hiện
thành công. Ground truth spraying đến từ harness; **Zeek metadata không thấy
username/password nên không tự chứng minh spraying trên nhiều tài khoản**.

Tham khảo: [OpenSSH client options](https://man.openbsd.org/ssh_config),
[OpenSSH server options](https://man.openbsd.org/sshd_config),
[ATT&CK Password Guessing](https://attack.mitre.org/techniques/T1110/001/),
[ATT&CK Password Spraying](https://attack.mitre.org/techniques/T1110/003/).

### Nmap scan

Dùng `-sT -Pn -n`, không NSE, không service/version probing. Tối đa 10 probes/s,
1 retry và host timeout 30s. Target/port cố định trong code; không có tham số
nhận IP Internet. Port scan: proxy 4443 và 4450–4455. Horizontal scan: backend
và DB port 22. Router chỉ mở đúng đường test này, cleanup xóa rule tạm.

Raw Nmap XML không ghi vào artifact. Chỉ parse để kiểm tra host/port coverage
và lưu số lượng state; partial/timed-out scan không đạt. Zeek lưu flow metadata.

Tham khảo: [Nmap TCP connect scanning](https://nmap.org/book/man-port-scanning-techniques.html),
[ATT&CK Network Service Discovery](https://attack.mitre.org/techniques/T1046/).

### TLS beacon và connection burst

Dùng curl đến HTTPS fixture có **certificate/cipher mạnh**, verify certificate.
Cùng tool/endpoint với benign health-check: fingerprint không là bằng chứng
duy nhất. Tối đa 80 requests/scenario, concurrency tối đa 2. Không tạo malware,
không thực hiện exfiltration hoặc truyền command C2. Response bỏ ngay trong
client bằng `-o /dev/null`, không đưa HTTP content vào collector.

Đây là mô phỏng timing/session pattern theo Word. Connection burst **không
được gọi là DoS đã xác nhận** khi chưa có bằng chứng ảnh hưởng availability.
Giữ benign periodic health-check, normal workload low/normal/busy, certificate
renewal và client-family change làm đối chiếu false positive.

Tham khảo: [ATT&CK Encrypted Channel](https://attack.mitre.org/techniques/T1573/).
HTTPS usage alone không đủ map [Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
như một C2 đã xác nhận.

### SSH lateral sequence và TLS interception

Giữ fixture v2 bằng tài khoản/key được ủy quyền và CA lab riêng.
`T1021.004`/`T1557` trong manifest là context của bài test; không biến mọi SSH
hay cert change thành tấn công. Lateral movement chưa có exploitation hay
credential theft. Interception có route/cert ground truth nhưng không có
credential/application content thật.

Tham khảo: [ATT&CK SSH](https://attack.mitre.org/techniques/T1021/004/),
[ATT&CK Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/).

## 4. File được thêm/sửa

| File | Vai trò |
|---|---|
| `experiments/campaign_attack_v3.json` | Quota tối thiểu 30k, giữ benign dư, quota chín attack family |
| `experiments/custom_dataset_attack_v3.json` | Scenario và giới hạn traffic |
| `src/data_generation/attacks.py` | Harness attack, kế thừa harness v2 |
| `docker/bastion/dataset-password-sshd.sh` | Password-auth fixture tạm |
| `docker/client/Dockerfile` | Thêm Nmap |
| `scripts/run_dataset_campaign.py` | Chọn scenario còn thiếu theo class/family |
| `src/features/aggregate_campaign.py` | Chọn subset và báo thiếu theo family |

Không tạo parser Zeek mới. Reuse `build_sessions.py`, `label_sessions.py`,
extended join, HMAC export và `validate_zeek_metadata.py`. Ground truth không
được lấy từ rule output. Manifest thêm execution tool, ATT&CK context và
evidence scope; tất cả là provenance, **không phải feature ML**.

## Output gọn: CSV record và ground truth

Thêm `--verbose` để hiện case đang chạy, IP nguồn/đích, port, protocol,
ground-truth label và profile crypto. Đây là endpoint dự kiến theo topology;
log Zeek có thể dùng IP sau NAT. Mỗi 15 giây có trạng thái và số lượt background
thành công/thất bại; số này là lượt thực thi, không phải số session dataset.
Không in password, private key, command đầy đủ hay raw response.

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/custom_data_v1" --verbose
```

Terminal hiển thị PREPARE → BACKGROUND/WARMUP → CASE START/DONE → GAP →
COOLDOWN → SENSOR/JOIN → CLEANUP → CSV UPDATED. Block 1 chỉ có background,
không có case attack. Flag chỉ thay đổi hiển thị, không đổi quota, traffic hay
nhãn và không tạo file verbose riêng. Process đang chạy giữ code đã load;
flag có hiệu lực ở lần resume tiếp theo. Không chạy hai process thu cùng lúc.

Nếu bạn chỉ muốn thao tác với hai CSV, tạo campaign mới bằng `--simple-output`
và bỏ `--parquet`:

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --campaign-id custom_attack_v1 --collect --simple-output

# Lần sau tiếp tục đúng campaign; chế độ gọn được nhớ trong checkpoint.
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/custom_attack_v1"
```

Tên `custom_attack_v1` do bạn đặt; cấu hình mặc định vẫn là attack v3.
Nếu folder đã tồn tại với chế độ cũ, dùng tên mới, ví dụ `custom_attack_csv`.
Các bước build client và bật Zeek extended bên dưới vẫn cần làm trước khi thu.

```text
data/lab_metadata/campaigns/custom_attack_v1/
├── dataset.csv             # một dòng/session, có feature và ground_truth_label
├── scenario_manifest.csv   # time window, host role, expected behavior và nhãn
└── .internal/              # checkpoint, schema, checksum, metadata Zeek để kiểm tra
```

Hai CSV được cập nhật sau mỗi round thành công. Resume ghi lại bảng tổng đã
khử trùng, không append thêm bản sao của session cũ. Quota và nhãn không đổi.
Dataset chỉ nhận session khớp manifest; session không rõ nhãn vẫn bị quarantine.
Đối chiếu hai CSV bằng `run_id` + `scenario_id`; không dùng nhãn làm feature ML.
Manifest có thể chứa window không được chọn vào subset cuối do quota.

Chế độ này không tạo manifest riêng cho từng scenario/kết nối nền, không xuất
các bản sample, missing-feature test hay train/validation/test CSV riêng.
Nó vẫn giữ metadata kiểm tra và trạng thái resume trong `.internal`, và log
Zeek dùng chung vẫn ở `data/lab_metadata/zeek`. Đây không phải chế độ chỉ lưu
đúng hai file trên toàn ổ đĩa. Đừng xóa `.internal` khi còn cần resume/audit.

CSV đang thu là bản tạm, có thể chưa đủ quota tối thiểu; xem `quota_complete` trong
output script trước khi coi campaign đã hoàn tất. Muốn chỉ chạy một round,
thêm `--max-runs 1`.

```powershell
# Kiểm tra bản nội bộ tương ứng với dataset.csv, dùng validator hiện có.
.\.venv\Scripts\python.exe data/schemas/validate_zeek_metadata.py --dataset "data/lab_metadata/campaigns/custom_attack_v1/.internal/dataset/training"
```

## 5. Chạy khi campaign cũ đã dừng

Không rebuild/recreate client giữa một round đang thu. Hoàn tất/dừng campaign
cũ và chờ cleanup trước. Campaign đang chạy vẫn giữ config và quota cũ.

```powershell
# Build client có Nmap và bật metadata extended.
docker compose build client zeek
$env:ZEEK_EXTENDED_METADATA = "true"
docker compose up -d
docker compose up -d --no-deps --force-recreate --wait zeek

# Smoke riêng: chạy mọi nhóm, không dùng như dataset nghiên cứu.
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --config experiments/campaign_attack_v3.json --campaign-id custom_attack_smoke --collect --smoke --parquet

# Campaign mới: thu 1 round lúc rảnh rồi dừng.
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --config experiments/campaign_attack_v3.json --campaign-id custom_attack_v3 --collect --max-runs 1 --parquet

# Tiếp tục campaign đó hôm khác; bỏ --max-runs nếu muốn chạy dài hơn.
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/custom_attack_v3" --max-runs 1 --parquet
```

Mặc định tạo campaign mới dùng attack v3. Resume luôn dùng config trong
checkpoint, không tự thay quota/scenario của campaign cũ. Cần campaign mới để
áp dụng profile mới; không sửa timestamp/nhãn các dataset đã thu.
Campaign mới lưu cả generation template và checksum vào checkpoint. Sửa file
JSON sau khi bắt đầu không tự thay protocol của campaign đang resume.

Budget vẫn 90 phút/block/lần invocation, soft limit; tối đa 60 round/block.
Giới hạn phút không cắt ngang round. Chạm cap khi còn thiếu có thể resume với
`--extra-rounds 10`. Không bảo đảm đủ quota hoàn thành trong 90 phút: phụ thuộc số
session từng hành vi và tốc độ máy. Mỗi round ghi actual execution windows.

## 6. Output và kiểm tra

Final subset dùng cho training/chia sẻ:
`data/lab_metadata/campaigns/custom_attack_v3/dataset/training/`.
Local log/join audit và manifest vẫn nằm ở cấu trúc hiện tại.

```powershell
.\.venv\Scripts\python.exe data/schemas/validate_zeek_metadata.py --dataset "data/lab_metadata/campaigns/custom_attack_v3/dataset/training"
```

Xem `campaign_summary.json`: class counts, scenario counts, shortfalls theo
family, actual dates và quota_complete. Xem `quality_report.json`: missing
field counts. Chưa đủ quota thì artifact là dataset đang thu, chưa gọi là final.

Port, fingerprint hay fixture cert có thể tạo shortcut. Cần đánh giá bỏ port,
temporal/device/fingerprint/unseen holdout và public data sau collection.
Sample từ v1 trước đây chỉ kiểm tra pipeline, không đại diện attack profile này.

## 7. Kiểm thử đã thực hiện và giới hạn

Unit/integration fixtures kiểm tra quota family, source/port bounds, rejection
proof, privacy và export. Container cô lập đã kiểm tra password authentication
thực sự bị từ chối, Nmap nhận open/closed port, và tài khoản/listener cleanup.
Không thay đổi lab/campaign đang chạy khi kiểm thử.

Chưa chạy full lab smoke v3 khi campaign cũ vẫn hoạt động. Chưa có dữ liệu
malware thực hoặc SSH compromise thực. Public dataset, fingerprint impersonation
và ECH thật vẫn là phạm vi riêng; không tuyên bố khớp 100% toàn bộ đề tài.
