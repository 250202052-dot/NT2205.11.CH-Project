# Kiểm tra dataset và chạy ba thí nghiệm A/B/C

## 1. Đã chuẩn bị những gì?

Dataset thu gốc: `data/lab_metadata/campaigns/custom_data_v1/dataset.csv`.
Không sửa/xóa dữ liệu này để cân bằng lớp. Code audit đọc toàn bộ dữ liệu,
đối chiếu manifest và dùng privacy validator sẵn có.

| File code/config | Công việc |
|---|---|
| scripts/audit_custom_dataset.py | Kiểm tra trùng session, nhãn/time window/endpoint, đếm thiếu và số mẫu scenario |
| scripts/prepare_custom_ablation.py | Chọn benign thật, giữ abnormal, xuất subset và split theo block |
| src/features/ablation_training.py | Đọc schema mới cho runner và tính thống kê từ vector gói |
| scripts/run_ablation.py | Runner hiện có, mở rộng để đọc lab-training-v2; train và tính metric A/B/C |
| src/models/baselines.py | Feature, tham số, preprocessing, CV và train dùng chung |
| src/models/ablation.py | Audit/reader, metric, ghi CSV và workflow A/B/C |
| experiments/ablation_custom_config.json | Đường dẫn cho lệnh --config cũ; không chứa tham số model |

Comment trong code giải thích từng bước. Không có logic đọc Zeek thứ hai:
audit dùng `assign_label`, model dùng feature đã có trong CSV.

## 2. Kiểm tra dữ liệu thu gốc

```powershell
.\.venv\Scripts\python.exe scripts/audit_custom_dataset.py
```

Output tại `experiments/results/dataset_audit/custom_data_v1/`:

- `audit.json`: PASS/FAIL, record trùng, sai nhãn, privacy và checksum nguồn.
- `scenario_counts.csv`: số session theo scenario, nhãn, protocol và block.
- `missing_fields.csv`: số ô trống theo field, cả toàn dataset và từng protocol.
- `README.md`: giải thích kết quả dễ đọc.

Trùng ở đây là trùng `(run_id, uid)`. Hai session độc lập có feature giống nhau
không tự động bị coi là trùng. Audit kiểm tra lại time window và endpoint qua
baseline nội bộ; không chỉ so sánh tên nhãn với một chuỗi trong manifest.
Nó từ chối dataset đang thu hoặc chưa hoàn tất, kiểm tra checksum trước khi đọc.

Privacy dùng `data/schemas/validate_zeek_metadata.py` qua API hiện có. Muốn chạy
CLI riêng:

```powershell
.\.venv\Scripts\python.exe data/schemas/validate_zeek_metadata.py --dataset "data/lab_metadata/campaigns/custom_data_v1/.internal/dataset/training"
```

Đừng đọc missing chung rồi kết luận mọi field hỏng: field SSH trống trên TLS
là bình thường, HTTP/DB không có metadata TLS/SSH. Với TLS 1.3, certificate và
server handshake signature có thể bị mã hóa, nên không quan sát được.
Validator kiểm tra allowlist và nội dung metadata, không chứng minh packet
capture tuyệt đối đầy đủ hoặc ground truth đại diện cho mạng doanh nghiệp.

## 3. Subset để train

```powershell
.\.venv\Scripts\python.exe scripts/prepare_custom_ablation.py
```

Bước này chỉ chạy khi audit PASS và checksum dữ liệu chưa thay đổi.
Output mặc định: `experiments/datasets/custom_data_v1_ablation/`.
Nếu folder đã có, script từ chối ghi đè; không cần chạy lại nếu đã chuẩn bị.
Muốn thử cách chọn khác, truyền một đường dẫn `--output` mới rồi sửa config
thí nghiệm tương ứng.

Dataset này có 30.000 session thật, không nhân bản hoặc SMOTE:

| Split | Block | Benign | Misconfiguration | Policy violation | Attack | Tổng |
|---|---|---:|---:|---:|---:|---:|
| Train | 1–3 | 16.500 | 450 | 450 | 600 | 18.000 |
| Validation | 4 | 5.250 | 225 | 225 | 300 | 6.000 |
| Test | 5 | 5.250 | 225 | 225 | 300 | 6.000 |

Benign chọn bằng seed cố định, phân theo block/protocol/hành vi. Không lấy
27.000 dòng đầu. Toàn bộ 3.000 abnormal của dataset cuối được giữ.
Flow/history feature tính từ quan sát đầy đủ được giữ nguyên; không tính lại
rate từ subset vì như vậy rate sẽ bị sai sau khi bỏ bớt benign.
Các session trong cùng run luôn nằm cùng split. Runner kiểm tra thời gian
không chồng lấn giữa train, validation và test.

File chính là `labeled_sessions.csv`; từng split nằm trong
`splits/train`, `splits/validation`, `splits/test`. Có schema, checksum,
privacy report và `preparation_summary.json` để đối chiếu.

## 4. Ba thí nghiệm

| Thí nghiệm | Feature |
|---|---|
| A — L3/L4 | Duration, bytes, packets, TCP state/history, port, flow rate/window counts, IAT, thống kê packet-size, TCP flag counts |
| B — TLS/SSH | Version, cipher, KEX/group, MAC, host-key, handshake/resumption, certificate metadata, JA3/JA4/HASSH/JA4SSH, TLS extensions/signature/ECH presence |
| C — Fused | Chính xác A + B |

Packet-size summary là mean/std/min/max từ vector đầu phiên có giới hạn,
không phải thống kê mọi gói của toàn session. TCP flags tách theo chiều và
thứ tự FIN/SYN/RST/PSH/ACK/URG/ECE/CWR. Chưa có retransmission count chính xác.
Không dùng host token, role, run/scenario ID, label, expected behavior, attack
family, alert hoặc rule output làm input. Không thêm history fingerprint/graph
vào B/C vì sẽ làm thí nghiệm vượt phạm vi TLS/SSH only.

Ba thí nghiệm dùng cùng 18k/6k/6k split và cả Random Forest, XGBoost, LightGBM.
Feature và tham số lấy từ `src/models/baselines.py`, seed 42, ba fold CV theo
thời gian và nhóm run, chỉ trên train. Không tuning/chọn depth. Preprocessing và
sample weight balanced được fit lại riêng từng fold; final test không tham gia CV.
Sau CV, fit lại trên toàn train, kiểm tra validation và đánh giá final test riêng.
CV hiển thị console; CSV lưu kết quả final test. Xem `report/MODEL_BASELINES.md`
để biết tham số, log1p, missing flags và one-hot encoder dùng chung.

Kiểm tra dữ liệu, chưa train và không tạo file:

```powershell
.\.venv\Scripts\python.exe scripts/run_ablation.py
```

Train cả A/B/C:

```powershell
.\.venv\Scripts\python.exe scripts/run_ablation.py --train
```

Dependency đã có trong `.venv` ở lần chuẩn bị này. Nếu tạo môi trường mới:

```powershell
.\.venv\Scripts\python.exe -m pip install -r experiments/requirements-baselines.txt
```

## 5. Đọc kết quả

Mỗi lần train chỉ lưu `experiments/results/custom_ablation/ketqua_lanN/summary.csv`.
N tự tăng, không ghi đè kết quả cũ. Audit không tạo thư mục/file.
CSV có chín dòng: A/B/C × ba model, cùng format baseline: accuracy, macro recall,
macro F1, MCC, AP attack, attack TPR/FPR, thời gian fit/predict; thêm tên nhóm/model.
Chỉ seed 42 nên suffix `_mean` là giá trị của lần final fit đó.
Thời gian chỉ đo model.fit/model.predict cuối, không gồm preprocessing, CV,
validation hoặc tính xác suất cho AP, đơn vị giây. Không xuất thêm JSON,
predictions hoặc ma trận feature. Kiểm tra privacy/checksum/split vẫn bắt buộc.

Xem TPR/FPR của attack bên cạnh macro-F1, không chỉ accuracy.
MCC đánh giá cả bốn nhãn; AP dùng xác suất attack và hữu ích khi attack ít.
AP phụ thuộc tỷ lệ attack, nên luôn đối chiếu trên cùng test split.
Đây là đánh giá theo thời gian trong một lab. Port fixture (4443/2223), phần mềm,
CA và topology có thể làm model học dấu hiệu riêng của lab; chưa chứng minh
cross-dataset, unseen-host hay khả năng phát hiện attack ngoài môi trường này.
Sau baseline, cần thí nghiệm bỏ port và fingerprint, rồi public/cross-source
evaluation theo yêu cầu đồ án. Không tối ưu lại config theo kết quả test hiện tại.
