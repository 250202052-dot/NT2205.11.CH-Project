# CUSTOM DATASET CHO METADATA-ONLY TLS/SSH THREAT DETECTION

> Tài liệu phục vụ proposal và chuẩn bị slide. Nội dung được viết theo trạng thái
> project ngày 12/10/2026.

## 1. Tóm tắt ngắn gọn

Project tự xây dựng một bộ dữ liệu mạng trong Docker lab để nghiên cứu phát hiện
hành vi bất thường trên TLS và SSH. Zeek chỉ thu metadata của kết nối, không lưu
nội dung HTTP, lệnh SSH, mật khẩu, file truyền, dữ liệu TLS đã giải mã hoặc session
secret.

Quá trình tạo dữ liệu được thiết kế như sau:

1. Traffic bình thường chạy liên tục trong lab.
2. Từng tình huống TLS/SSH bất thường được chèn vào những khoảng thời gian có kiểm soát.
3. Mỗi tình huống được ghi vào manifest để biết thời gian, nguồn, đích và nhãn đúng.
4. Session Zeek được ghép với manifest để tạo dữ liệu có nhãn.
5. Dataset được kiểm tra trùng lặp, kiểm tra nhãn và chạy privacy validator.
6. Một subset 30.000 session được chuẩn bị cho huấn luyện và đánh giá mô hình.

Số liệu hiện tại cần phân biệt rõ:

| Phạm vi | Số session | Mục đích |
|---|---:|---|
| Toàn bộ custom dataset đã audit | 182.240 | Lưu đầy đủ traffic hợp lệ đã thu |
| Subset dùng cho ML | 30.000 | So sánh mô hình và ablation study |
| Tập train | 18.000 | Học tham số mô hình |
| Tập validation | 6.000 | Kiểm tra trong quá trình phát triển |
| Tập test | 6.000 | Đánh giá cuối cùng |

Các con số trong tài liệu là snapshot của `dataset.csv` đã audit. Đợt thu bổ sung
đang thực hiện chưa được tính vào bảng trên cho đến khi round hoàn thành, ghép nhãn
thành công và audit lại.

## 2. Mục tiêu của custom dataset

Custom dataset giải quyết ba nhu cầu chính:

- Có ground truth rõ ràng cho từng tình huống TLS/SSH.
- Có đủ metadata để chạy Rule Engine, Machine Learning, Deep Learning và correlation.
- Bảo đảm nguyên tắc metadata-only: `f_L7(raw) = ∅`.

Dataset không nhằm khẳng định rằng mọi bất thường đều là tấn công. Project sử dụng
bốn nhãn riêng:

| Nhãn | Ý nghĩa dễ hiểu | Ví dụ |
|---|---|---|
| `benign` | Hoạt động bình thường hoặc thay đổi đã được cho phép | TLS hiện đại, SSH hợp lệ, gia hạn certificate |
| `misconfiguration` | Cấu hình sai nhưng chưa đủ bằng chứng là tấn công | Certificate hết hạn, sai hostname, khóa yếu |
| `policy_violation` | Kết nối vi phạm chính sách an toàn | Cipher/KEX/MAC yếu, SSH đi theo đường mới |
| `attack_behavior` | Hành vi được thực thi theo kịch bản tấn công trong lab | Password guessing, scan, beacon, lateral sequence |

`attack_behavior` là ground truth của hoạt động có kiểm soát trong lab. Nó không có
nghĩa là hệ thống đã bị compromise thật hoặc đang chạy malware thật.

## 3. Topology dùng để sinh dữ liệu

Lab có bảy service chạy chính và một `client` được tạo khi cần sinh traffic:

| Service | Vai trò |
|---|---|
| `client` | Service tạm để sinh truy cập bình thường và thực hiện các scenario được cho phép |
| `proxy` | Reverse proxy TLS; thay đổi TLS/certificate cho các case kiểm thử |
| `web-frontend` | Giao diện web bán hàng |
| `backend` | API của ứng dụng web |
| `db` | PostgreSQL lưu dữ liệu ứng dụng |
| `bastion` | SSH jump host/ProxyJump |
| `router` | Alpine router, NAT, IP forwarding và firewall rule tạm |
| `zeek` | Sensor quan sát traffic và ghi metadata |

Luồng web chính:

```text
Client -> Reverse Proxy -> Web Frontend -> Backend -> Database
```

Luồng SSH chính:

```text
Client -> Bastion/Jump Host -> Backend hoặc Database
```

Zeek quan sát các luồng mạng trong lab nhưng không lưu raw payload tầng ứng dụng.

## 4. Những task đã thực hiện

| STT | Task | Kết quả | Trạng thái |
|---:|---|---|---|
| 1 | Xây dựng Docker topology | Web tách frontend/backend/DB; có proxy, bastion, router và Zeek | Hoàn thành |
| 2 | Cấu hình Zeek JSON | Thu `conn`, `ssl`, `x509`, `ssh`, `notice`, `weird` | Hoàn thành |
| 3 | Bổ sung extended metadata | IAT, packet-size vector, TCP flags, TLS extensions, signature scheme | Hoàn thành |
| 4 | Tạo benign background | HTTP nội bộ, DB, TLS hiện đại và SSH được ủy quyền chạy xuyên suốt | Hoàn thành |
| 5 | Tạo scenario TLS/SSH | Cấu hình yếu, certificate lỗi, guessing, spraying, scan, beacon, lateral và interception | Hoàn thành |
| 6 | Tạo ground-truth manifest | Lưu time window, role nguồn/đích, protocol, hành vi mong đợi và nhãn | Hoàn thành |
| 7 | Join session với manifest | Ghép `conn/ssl/x509/ssh/notice` theo session, thời gian và endpoint | Hoàn thành |
| 8 | Xuất dataset | CSV metadata-only, schema, version và checksum | Hoàn thành |
| 9 | Kiểm tra chất lượng | Kiểm tra trùng, sai nhãn, missing field, scenario coverage | Hoàn thành |
| 10 | Kiểm tra privacy | Không có raw IP trong training export và không có raw L7 | Hoàn thành |
| 11 | Chuẩn bị tập ML | Chọn 30.000 session thật, không SMOTE và không nhân bản record | Hoàn thành |
| 12 | Chia dữ liệu theo thời gian | Train 18.000, validation 6.000, test 6.000 | Hoàn thành |
| 13 | Ablation A/B/C | So sánh L3/L4, TLS/SSH và fused feature | Đã có code |
| 14 | Baseline model | Random Forest, XGBoost và LightGBM | Hoàn thành lượt baseline |
| 15 | Scenario đối chứng bổ sung | Thêm hành vi chậm/biến thiên và benign tương tự attack | Code hoàn thành, đang bổ sung dữ liệu |

## 5. Quy trình tạo một record có nhãn

Quy trình có thể trình bày bằng sáu bước:

```text
Sinh traffic
    -> Zeek ghi metadata JSON
    -> Manifest ghi thời gian và nhãn đúng
    -> Ghép các log theo session
    -> Ghép session với manifest
    -> Kiểm tra privacy và xuất CSV
```

### Bước 1: Chạy benign background

Các hoạt động bình thường chạy cả trước, trong và sau scenario. Điều này tránh tạo
dataset theo kiểu “lúc bình thường chỉ có normal, lúc tấn công chỉ có attack”. Trong
một thời điểm có thể đồng thời tồn tại nhiều session bình thường và session scenario.

### Bước 2: Thực hiện scenario

Scenario được thực thi bằng công cụ thật trong phạm vi Docker lab, ví dụ:

- `curl` và OpenSSL cho TLS.
- OpenSSH cho SSH authentication và ProxyJump.
- Nmap TCP connect cho network discovery có giới hạn.
- Nginx cho TLS certificate/profile và interception fixture.

### Bước 3: Ghi manifest

Mỗi scenario có các thông tin chính:

```text
scenario_id
start_time
end_time
src_role
dst_role
protocol
expected_behavior
expected_rule
ground_truth_label
```

Manifest trả lời câu hỏi: hoạt động nào đã được thực hiện, diễn ra lúc nào, từ đâu
đến đâu và nhãn đúng là gì.

### Bước 4: Ghép log Zeek thành session

Pipeline tái sử dụng `build_sessions.py` để ghép:

- `conn.log`: thông tin kết nối L3/L4.
- `ssl.log`: phiên TLS và handshake.
- `x509.log`: metadata certificate.
- `ssh.log`: phiên bản và thuật toán SSH.
- `notice.log`: thông báo policy/rule khi có.

`weird.log` phục vụ kiểm tra sensor và lỗi protocol; không lấy raw payload.

### Bước 5: Gán nhãn

Session chỉ được gán nhãn scenario khi phù hợp với:

- Khoảng thời gian của scenario.
- Protocol.
- Source role và destination role.
- Session/endpoint mong đợi.

Record không khớp chắc chắn không bị ép thành benign. Nó được đưa vào quarantine để
kiểm tra.

### Bước 6: Kiểm tra và xuất dữ liệu

Pipeline kiểm tra schema, checksum, field cấm, nhãn và privacy trước khi sử dụng cho
ML.

## 6. Các scenario đã có trong dataset được audit

### 6.1 Benign: 179.240 session

| Scenario/behavior | Số session | Ý nghĩa |
|---|---:|---|
| `authorized_background` | 153.551 | HTTP/DB/SSH background được cho phép |
| `trusted_modern_tls` | 25.162 | TLS hiện đại với certificate tin cậy |
| `tls_benign_client_change` | 203 | Thay đổi client hợp lệ |
| `tls_benign_renewal` | 164 | Gia hạn/thay certificate hợp lệ |
| `tls_benign_healthcheck` | 118 | HTTPS health check bình thường |
| `tls_session_resumption` | 42 | TLS session resumption hợp lệ |
| **Tổng** | **179.240** | |

### 6.2 Misconfiguration: 900 session

| Scenario | Số session | Ý nghĩa |
|---|---:|---|
| `tls_hostname_mismatch` | 393 | Hostname truy cập không khớp certificate |
| `tls_weak_key` | 293 | Certificate sử dụng khóa không đạt policy |
| `tls_expired_cert` | 214 | Certificate đã hết hạn |
| **Tổng** | **900** | |

### 6.3 Policy violation: 900 session

| Scenario | Số session | Ý nghĩa |
|---|---:|---|
| `tls_unexpected_certificate` | 204 | Certificate thay đổi ngoài baseline mong đợi |
| `ssh_weak_mac` | 198 | SSH sử dụng MAC yếu |
| `ssh_weak_host_key` | 131 | Thuật toán host key không đạt policy |
| `ssh_new_path` | 119 | Xuất hiện đường SSH mới |
| `tls_weak_cipher` | 94 | TLS cipher không được policy cho phép |
| `ssh_weak_cipher` | 90 | SSH cipher yếu |
| `ssh_weak_kex` | 64 | SSH key exchange yếu |
| **Tổng** | **900** | |

### 6.4 Attack behavior: 1.200 session

| Scenario | Số session | Cách thực hiện trong lab |
|---|---:|---|
| `ssh_password_guessing` | 180 | Nhiều mật khẩu sai vào một tài khoản lab |
| `nmap_tcp_connect_scan` | 160 | TCP connect scan các port cố định của proxy |
| `tls_beacon_jitter` | 160 | Kết nối TLS định kỳ với khoảng nghỉ thay đổi |
| `tls_beacon_burst` | 140 | Nhóm kết nối TLS ngắn rồi nghỉ |
| `ssh_password_spraying` | 120 | Một mật khẩu sai thử trên nhiều tài khoản lab |
| `nmap_ssh_horizontal_scan` | 120 | Discovery SSH trên backend và DB |
| `ssh_lateral_sequence` | 120 | Chuỗi ProxyJump tới nhiều host nội bộ |
| `tls_connection_burst` | 120 | Nhiều kết nối TLS trong một khoảng ngắn |
| `tls_interception_fixture` | 80 | TLS proxy dùng CA lab riêng trước TLS upstream |
| **Tổng** | **1.200** | |

## 7. Thống kê toàn bộ dữ liệu đã audit

### 7.1 Phân bố nhãn

| Nhãn | Số session | Tỷ lệ |
|---|---:|---:|
| `benign` | 179.240 | 98,354% |
| `attack_behavior` | 1.200 | 0,658% |
| `policy_violation` | 900 | 0,494% |
| `misconfiguration` | 900 | 0,494% |
| **Tổng** | **182.240** | **100%** |

Tỷ lệ này phản ánh toàn bộ traffic thực tế đã giữ lại từ các round. Nó rất mất cân
bằng vì benign background chạy liên tục. Đây là điều bình thường với dữ liệu giám sát
mạng, nhưng cần xử lý cẩn thận khi đánh giá model.

### 7.2 Phân bố protocol quan sát được

| Nhóm | Số session | Giải thích |
|---|---:|---|
| TLS | 27.387 | Zeek nhận diện được TLS |
| SSH | 6.485 | Zeek nhận diện được SSH |
| L3/L4/conn-only | 148.368 | Có flow metadata nhưng application protocol để trống |
| **Tổng** | **182.240** | |

Application protocol trống không đồng nghĩa record hỏng. Các flow HTTP nội bộ, DB
hoặc kết nối chỉ được nhận diện ở mức `conn.log` vẫn cung cấp feature L3/L4.

### 7.3 Độ dài session

| Duration | Số session |
|---|---:|
| Dưới 1 giây | 177.939 |
| Từ 1 đến dưới 5 giây | 2.482 |
| Từ 5 đến dưới 30 giây | 1.669 |
| Từ 30 đến dưới 120 giây | 74 |
| Từ 120 giây trở lên | 76 |

Phần lớn session ngắn do web/API request, health check và các kết nối fixture trong
lab. Đây cũng là một hạn chế cần nêu khi đánh giá khả năng tổng quát hóa.

### 7.4 TLS và certificate

| Thông tin | Số lượng |
|---|---:|
| TLS 1.2 | 19.040 session |
| TLS 1.3 | 8.347 session |
| Tổng TLS | 27.387 session |
| Certificate fingerprint khác nhau | 12 |
| TLS session không quan sát được certificate | 8.382 |

TLS 1.3 có thể mã hóa một phần handshake/certificate nên field certificate thiếu
không tự động được xem là lỗi thu thập.

### 7.5 Khoảng thời gian thực tế

Dataset hiện tại được thu trong hai ngày UTC:

```text
2026-10-09
2026-10-10
```

Campaign có năm block logic để chia quota và chia dữ liệu. Năm block không có nghĩa
là năm ngày lịch thật. Timestamp trong record là thời gian thu thật và không bị sửa.

## 8. Subset 30.000 session dùng cho Machine Learning

Toàn bộ 3.000 session không phải benign được giữ lại. Benign được lấy mẫu có kiểm
soát theo block, protocol và hành vi với seed `2205`. Không dùng SMOTE và không nhân
bản record.

### 8.1 Phân bố nhãn

| Nhãn | Số session | Tỷ lệ |
|---|---:|---:|
| `benign` | 27.000 | 90% |
| `misconfiguration` | 900 | 3% |
| `policy_violation` | 900 | 3% |
| `attack_behavior` | 1.200 | 4% |
| **Tổng** | **30.000** | **100%** |

### 8.2 Chia train, validation và test

| Split | Block | Benign | Misconfig | Policy | Attack | Tổng |
|---|---|---:|---:|---:|---:|---:|
| Train | 1–3 | 16.500 | 450 | 450 | 600 | 18.000 |
| Validation | 4 | 5.250 | 225 | 225 | 300 | 6.000 |
| Test | 5 | 5.250 | 225 | 225 | 300 | 6.000 |

Việc chia được thực hiện theo block/thời gian và giữ toàn bộ session của cùng một run
trong cùng split. Không random từng dòng giữa train và test.

## 9. Feature của dataset

Schema training hiện có 112 cột:

```text
112 cột trong dataset
├── 88 feature đầu vào model
└── 44 cột quản lý, ground truth hoặc chưa chọn cho baseline
```

### 9.1 Ba nhóm thí nghiệm

| Experiment | Feature sử dụng |
|---|---|
| A — L3/L4 | 44 trường về duration, bytes, packet, rate, port, TCP state, IAT, packet size và TCP flags |
| B — TLS/SSH | 44 trường về TLS/certificate/JA3/JA4 và SSH/KEX/cipher/MAC/HASSH/JA4SSH |
| C — Fused | A + B, tổng cộng 88 trường gốc |

Sau tiền xử lý, 88 trường của nhóm C trở thành 421 cột cho model:

```text
57 trường số
+ 57 cờ đánh dấu giá trị số bị thiếu
+ 307 cột one-hot từ 31 trường phân loại
= 421 cột
```

421 là số cột sau mã hóa, không phải 421 loại metadata gốc.

### 9.2 Những trường không đưa vào model

Các trường label, scenario, ID, host token, certificate token và ground-truth source
không được dùng làm đầu vào. Mục đích là tránh data leakage và tránh để model ghi nhớ
host/certificate cụ thể của lab.

Các vector chuỗi như `pkt_size_vector` và `tcp_flags_orig/resp` chưa đưa trực tiếp
vào baseline cây quyết định. Pipeline sử dụng thống kê mean/std/min/max và số lượng
từng TCP flag.

## 10. Kết quả kiểm tra chất lượng

Audit hiện tại cho kết quả:

| Kiểm tra | Kết quả |
|---|---|
| Tổng session | 182.240 |
| Trùng `(run_id, uid)` | 0 |
| Sai mapping manifest | 0 |
| Quota campaign | Đủ |
| Privacy validator | PASS |
| Raw IP trong training export | 0 cột |
| Raw L7 trong training export | 0 cột |
| Feature version | `lab-training-v2` |
| Label version | `lab-label-v1` |

Missing value không luôn là lỗi:

- Record TLS thường không có field SSH.
- Record SSH thường không có field TLS/X.509.
- Flow conn-only không có metadata TLS/SSH.
- TLS 1.3 có thể làm certificate hoặc signature không quan sát được.

Numeric missing được điền bằng median của tập train và có thêm cờ missing. Categorical
missing được chuyển thành `__MISSING__`; category xuất hiện dưới 5 lần được gom vào
nhóm hiếm.

## 11. Baseline model hiện tại

Ba model đã được so sánh trên feature group C:

| Model | Accuracy | Macro Recall | Macro F1 | MCC | TPR attack | FPR attack |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest | 99,30% | 95,65% | 95,55% | 96,97% | 100% | 0,175% |
| XGBoost | 99,10% | 94,71% | 95,08% | 96,06% | 95,33% | 0,140% |
| LightGBM | 99,05% | 94,49% | 94,79% | 95,84% | 94,00% | 0,123% |

Random Forest đang tốt nhất về accuracy, macro recall, macro F1, MCC và TPR attack.
XGBoost có AP attack cao hơn một chút; LightGBM có FPR attack thấp nhất. Vì vậy kết
quả hiện tại chỉ cho phép nói Random Forest là baseline tốt nhất tổng thể trên test
split hiện tại, chưa chứng minh nó tốt nhất trên mạng bên ngoài lab.

Model Random Forest đã được lưu tại:

```text
src/models/random_forest_fused.joblib
```

## 12. Scenario bổ sung để giảm model học tắt

Code đã bổ sung các cặp attack/benign có hành vi gần giống nhau:

| Nhóm bổ sung | Attack/policy | Benign đối chứng |
|---|---|---|
| TLS định kỳ | `tls_beacon_slow`, `tls_beacon_variable` | `tls_benign_periodic` |
| TLS burst | `tls_connection_burst_variable` | `tls_benign_burst` |
| SSH password | `ssh_password_guessing_slow`, `ssh_password_spraying_slow` | `ssh_benign_password_retry` |
| SSH nhiều đích | `ssh_lateral_variable` | `ssh_benign_lateral_variable` |
| TLS certificate route | `tls_interception_sameport` | TLS hiện đại cùng endpoint trước mỗi case |
| TLS policy | `tls_policy_regression` | TLS hiện đại cùng endpoint trước case |

Mục đích của benign đối chứng là ngăn model học những quy tắc quá đơn giản như:

- “Cứ truy cập định kỳ là beacon”.
- “Cứ đăng nhập SSH sai là attack”.
- “Cứ kết nối nhiều host là lateral movement”.
- “Cứ dùng port fixture là attack”.

Các scenario này chưa được cộng vào số 182.240 cho đến khi round bổ sung hoàn thành
và dataset được audit lại.

## 13. Hạn chế cần trình bày trung thực

1. Dataset được tạo trong Docker lab đóng, chưa đại diện cho toàn bộ mạng doanh nghiệp.
2. Thời gian thực tế hiện mới bao phủ hai ngày UTC.
3. Một số port, certificate, phần mềm và fingerprint có thể trở thành dấu hiệu riêng của lab.
4. Tổng dataset rất mất cân bằng; accuracy cao một mình không đủ để kết luận model tốt.
5. TLS 1.3 làm một số metadata certificate/handshake không quan sát được.
6. Zeek metadata không nhìn thấy username, password, lệnh SSH hoặc nội dung TLS.
7. Nhãn attack đến từ scenario được thực thi, không phải bằng chứng compromise thật.
8. Đánh giá hiện tại là temporal split trong cùng lab, chưa phải cross-dataset hoặc unseen-host test.

Do đó báo cáo cần dùng Macro F1, MCC, AP, TPR và FPR bên cạnh accuracy.

## 14. Các task tiếp theo

| Ưu tiên | Task | Kết quả mong đợi |
|---:|---|---|
| 1 | Hoàn thành round scenario bổ sung | Có thêm attack chậm/biến thiên và benign đối chứng |
| 2 | Chạy lại audit và privacy validator | Xác nhận không trùng, không sai nhãn, không raw L7 |
| 3 | Refresh subset ML | Giữ dữ liệu cũ và đưa dữ liệu mới vào test theo thời gian |
| 4 | Chạy lại A/B/C ablation | Đo đóng góp riêng của L3/L4 và TLS/SSH metadata |
| 5 | Chạy lại ba baseline model | So sánh RF, XGBoost, LightGBM trên dataset mới |
| 6 | Kiểm thử bỏ port/fingerprint | Đo mức độ model đang học dấu hiệu riêng của lab |
| 7 | Unseen scenario/host holdout | Kiểm tra khả năng tổng quát hóa |
| 8 | Public/cross-source evaluation | Đối chiếu với NF-UQ, IoT-23, CESNET hoặc CTU nếu schema phù hợp |
| 9 | Rule + ML correlation | Kết hợp alert policy với xác suất model và lịch sử session |
| 10 | Agentic response simulator | Đề xuất phản ứng có giới hạn, có policy guard và verifier |

## 15. Nội dung rút gọn để đưa vào slide

### Slide 1 — Mục tiêu custom dataset

- Xây dựng dataset TLS/SSH có ground truth trong Docker lab.
- Benign traffic chạy liên tục; scenario bất thường được chèn theo time window.
- Thu metadata L3–L6, không thu raw L7 hoặc secret.
- Phân biệt bốn nhãn: benign, misconfiguration, policy violation và attack behavior.

**Câu nói khi trình bày:**

> Dataset không mặc định coi mọi bất thường là tấn công. Nhãn được xác định từ hoạt
> động có kiểm soát và manifest của lab.

### Slide 2 — Quy trình sinh dữ liệu

```text
Docker traffic -> Zeek JSON -> Session join -> Manifest join
               -> Privacy/quality validation -> Labeled dataset
```

- Zeek logs: `conn`, `ssl`, `x509`, `ssh`, `notice`, `weird`.
- Manifest chứa time window, source/destination role, protocol và ground truth.
- Session không khớp chắc chắn được quarantine.

### Slide 3 — Scenario chính

- TLS: weak cipher, weak key, expired certificate, hostname mismatch.
- SSH policy: weak KEX, cipher, MAC, host key và new path.
- Attack behavior: password guessing/spraying, Nmap scan, TLS beacon/burst,
  SSH lateral sequence và TLS interception fixture.
- Benign đối chứng: modern TLS, authorized SSH, health check, session resumption,
  certificate renewal và client change.

### Slide 4 — Thống kê dataset

| Nội dung | Kết quả |
|---|---:|
| Tổng session đã audit | 182.240 |
| Benign | 179.240 |
| Misconfiguration | 900 |
| Policy violation | 900 |
| Attack behavior | 1.200 |
| Trùng session | 0 |
| Sai nhãn so với manifest | 0 |
| Privacy validator | PASS |

### Slide 5 — Dataset cho ML

- Subset 30.000 session: 90% benign và 10% ba nhóm bất thường.
- Train/validation/test: 18.000/6.000/6.000.
- Chia theo thời gian và run, không random từng record.
- Không dùng SMOTE, không nhân bản attack.
- 88 feature gốc; 421 cột sau missing flags và one-hot encoding.

### Slide 6 — Kết quả sơ bộ

- Random Forest tốt nhất tổng thể trên test hiện tại.
- Accuracy 99,30%; Macro F1 95,55%; MCC 96,97%.
- TPR attack 100%; FPR attack 0,175%.
- Kết quả mới chỉ phản ánh closed lab và cần unseen/cross-source evaluation.

### Slide 7 — Đóng góp và công việc tiếp theo

**Đóng góp:**

- Pipeline tạo dữ liệu có thể resume.
- Ground truth dựa trên manifest, không dựa vào detector alert.
- Metadata-only và có privacy validation.
- Hỗ trợ Rule Engine, ML/DL và correlation.

**Tiếp theo:**

- Thu xong scenario chậm/biến thiên và benign đối chứng.
- Audit lại và chạy A/B/C ablation.
- Kiểm thử bỏ port/fingerprint, unseen host/scenario và public dataset.

## 16. Các file quan trọng

| File/thư mục | Mục đích |
|---|---|
| `data/lab_metadata/campaigns/custom_data_v1/dataset.csv` | Toàn bộ custom dataset công khai hiện tại |
| `data/lab_metadata/campaigns/custom_data_v1/scenario_manifest.csv` | Ground truth theo time window và role |
| `experiments/datasets/custom_data_v1_ablation/` | Subset 30.000 session cho ML |
| `scripts/run_dataset_campaign.py` | Chạy/resume chiến dịch thu dữ liệu |
| `scripts/audit_custom_dataset.py` | Kiểm tra nhãn, trùng, missing và privacy |
| `scripts/prepare_custom_ablation.py` | Chuẩn bị subset và split theo thời gian |
| `src/features/build_sessions.py` | Ghép các log Zeek thành session |
| `src/features/training_dataset.py` | Chuẩn hóa schema, privacy và historical feature |
| `src/models/baselines.py` | Tiền xử lý và train ba baseline model |
| `src/models/random_forest_fused.joblib` | Random Forest đã xuất |

## 17. Lệnh cập nhật sau khi thu bổ sung xong

```powershell
.\.venv\Scripts\python.exe -X utf8 scripts/audit_custom_dataset.py
.\.venv\Scripts\python.exe -X utf8 scripts/prepare_custom_ablation.py --refresh
.\.venv\Scripts\python.exe -X utf8 scripts/check_dataset_quality.py
.\.venv\Scripts\python.exe -X utf8 scripts/run_ablation.py --train
.\.venv\Scripts\python.exe -X utf8 scripts/run_model_baselines.py --train
.\.venv\Scripts\python.exe -X utf8 scripts/run_model_baselines.py --export-rf
```

Chỉ cập nhật số liệu trên slide sau khi audit mới trả về PASS.
