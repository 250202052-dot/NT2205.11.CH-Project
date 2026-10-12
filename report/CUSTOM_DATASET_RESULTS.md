# Audit và baseline A/B/C của custom_data_v1

Đây là kết quả đã chạy trên dữ liệu thu thật, không phải fixture của unit test.
Dataset thu gốc giữ nguyên; subset được xuất riêng cho thí nghiệm.

## Kiểm tra dataset thu gốc

| Nội dung | Kết quả |
|---|---:|
| Session kiểm tra | 182.240 |
| Trùng khóa `(run_id, uid)` | 0 |
| Sai nhãn/identity/time window so với manifest | 0 |
| Privacy validator | PASS |
| Benign | 179.240 |
| Misconfiguration | 900 |
| Policy violation | 900 |
| Attack behavior | 1.200 |

Đối chiếu manifest xác nhận nhãn nhất quán với lịch scenario trong lab,
không chứng minh từng connection có compromise/malware. Hai session riêng
có feature giống nhau không bị coi là bản ghi trùng.

Files chi tiết:

- `experiments/results/dataset_audit/custom_data_v1/audit.json`
- `experiments/results/dataset_audit/custom_data_v1/scenario_counts.csv`
- `experiments/results/dataset_audit/custom_data_v1/missing_fields.csv`

## Field thiếu cần lưu ý

| Field/nhóm | Phạm vi session | Tỷ lệ thiếu |
|---|---|---:|
| TLS version, cipher, JA4 | TLS | 0% |
| Certificate key bits, signature algorithm, SPKI token | TLS | 30,606% |
| Server handshake signature scheme | TLS | 30,949% |
| SSH KEX/cipher/MAC/host-key/HASSH | SSH | 7,587% |
| SSH protocol version và JA4SSH | SSH | 0% |
| IAT mean, packet-size vector | TLS/SSH | 0% ô trống |

Trong 8.382 session TLS thiếu key bits, 8.347 là TLS 1.3 và 35 là TLS 1.2.
Certificate TLS 1.3 bị mã hóa nên sensor thụ động không thấy; phần thiếu không
được điền giả. 35 phiên TLS 1.2 còn lại cần xem handshake/session completeness
nếu muốn phân tích sâu. SSH thiếu thuật toán vẫn có protocol metadata;
chưa suy ra nguyên nhân cụ thể chỉ từ tỷ lệ thiếu này.

0% ô trống của packet/IAT không đồng nghĩa mọi phiên có đủ số gói để tính
thống kê ổn định; xem thêm các cột số gói/IAT count và sequence_truncated.
Không dùng tỷ lệ thiếu của toàn dataset để đánh giá field riêng TLS hoặc SSH.

## Subset và split

Subset `experiments/datasets/custom_data_v1_ablation/` có 30.000 session:
27.000 benign, 900 misconfiguration, 900 policy violation và 1.200 attack.
Giữ tất cả abnormal; chọn benign thật phân theo block/protocol/hành vi với
seed 2205. Các feature flow/history giữ từ collection đầy đủ.

| Split | Block | Session |
|---|---|---:|
| Train | 1–3 | 18.000 |
| Validation | 4 | 6.000 |
| Test | 5 | 6.000 |

Không chia một run qua hai split, thời gian các split không chồng lấn.
Master và từng split vượt privacy validator; checksum bảo vệ nguồn thí nghiệm.

## Kết quả Random Forest

Cùng split, feature preprocessing chỉ fit trên train. Mỗi thí nghiệm chạy
ba seed 2205/42/2026, 100 trees, class_weight=balanced, min_samples_leaf=2.
Chọn depth 12 hoặc không giới hạn bằng validation macro-F1.

| Experiment | Feature | Test macro-F1 trung bình ± std | Attack recall trung bình | Benign false-alarm rate trung bình |
|---|---|---:|---:|---:|
| A | L3/L4 + packet metadata | 94,05% ± 0,19 điểm % | 99,11% | 0,057% |
| B | TLS/SSH metadata | 85,10% ± 0,00 điểm % | 76,67% | 3,010% |
| C | A + B | 95,59% ± 0,11 điểm % | 99,11% | 0,057% |

Macro-F1 là trung bình F1 của bốn nhãn, không phải accuracy.
Std là độ lệch giữa ba seed model trên cùng split, không phải confidence interval.
Kết quả B trùng nhau giữa seed là kết quả quan sát, không đủ căn cứ nói model
ổn định trên mọi dataset. C có macro-F1 cao nhất trong lần chạy này; chưa có
kiểm định để kết luận mức tăng có ý nghĩa thống kê.

Kết quả chi tiết tại:
`experiments/results/custom_ablation/20261010T155425Z_59aa11/`.
`results.json` có metric từng lớp, confusion matrix và kết quả validation;
`summary.csv` có mean/std; prediction CSV dùng phân tích lỗi.
Phiên bản: scikit-learn 1.9.1, numpy 2.4.3.

## Giới hạn để ghi trong báo cáo

Đây là temporal split trong một topology lab. Port fixture, CA, phiên bản phần
mềm và cách sinh traffic có thể trở thành shortcut. Normal có cả HTTP/DB,
còn một số attack chỉ có flow TCP: B thiếu TLS/SSH trên những session đó.
Kết quả chưa chứng minh phát hiện cross-dataset, host mới hoặc scenario chưa
từng thấy. Cần thí nghiệm bỏ port/fingerprint và dữ liệu public/cross-source
trước khi đưa ra kết luận tổng quát. Không chọn lại model bằng test này.

Lệnh tái chạy và giải thích code trong `report/CUSTOM_DATASET_AUDIT_ABLATION.md`.
