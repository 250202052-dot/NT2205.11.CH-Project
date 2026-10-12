# Profile custom dataset đang được cấu hình

Đối chiếu cấu hình ngày 10/10/2026. Đây là mô tả thiết kế và triển khai,
không phải kết quả thực nghiệm đã thu xong.

## Cấu hình được chọn

- Collection profile: `lab-v3-attacks`.
- Campaign: `experiments/campaign_attack_v3.json`.
- Generation template: `experiments/custom_dataset_attack_v3.json`.
- 23 scenario được khai báo: 4 benign, 3 misconfiguration,
  7 policy_violation và 9 attack_behavior; ngoài ra có background liên tục.
- Tên folder như `custom_attack_v1` là tên campaign do người dùng đặt,
  không quyết định phiên bản profile.
- Campaign mới dùng cấu hình hiện tại. Resume dùng template/quota trong
  checkpoint cũ, không tự chuyển sang profile mới.

## Phân bố mục tiêu

| Nhãn | Quota mục tiêu | Tỷ lệ thiết kế |
|---|---:|---:|
| benign | Ít nhất 27.000 | 90% |
| misconfiguration | 900 | 3% |
| policy_violation | 900 | 3% |
| attack_behavior | 1.200 | 4% |
| Tổng tối thiểu | 30.000 | 100% |

Giữ benign dư hợp lệ của các round hoàn tất, nên tổng có thể vượt 30.000.
Tỷ lệ cuối phải lấy từ `class_counts`/`class_percentages`, không chép quota
thành số liệu thực nghiệm. Tỷ lệ này do lab thiết kế, không đo prevalence
ngoài doanh nghiệp. Đơn vị đếm là session duy nhất `(run_id, uid)`.

## Benign

Background chạy trong suốt mỗi round: HTTPS client→proxy, HTTP
frontend→backend, PostgreSQL backend→DB và SSH quản trị qua bastion.
Không khẳng định background chạy khi máy tắt hoặc giữa hai lần gọi script.

| Scenario | Hoạt động |
|---|---|
| tls_benign_renewal | Đổi certificate được cho phép; client tin certificate mới |
| tls_benign_healthcheck | HTTPS kiểm tra dịch vụ định kỳ; mẫu đối chứng với beacon |
| tls_session_resumption | OpenSSL reconnect, kiểm tra phiên TLS được tái sử dụng |
| tls_benign_client_change | Đổi họ client curl/OpenSSL; không phải nâng cấp phiên bản phần mềm thật |

TLS background chọn TLS 1.2/1.3. Listener modern 443 cho TLS 1.2 dùng
ECDHE-RSA-AES128/256-GCM; TLS 1.3 do client/server thương lượng.
Listener fixture 4443 hiện dùng TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256 cho
các request modern. Certificate RSA 2048-bit, chữ ký SHA-256.
Thuật toán thực sự thương lượng phải đối chiếu `ssl.log`/`ssh.log`.

## Misconfiguration

| Scenario | Cấu hình thử nghiệm | Rule dự kiến |
|---|---|---|
| tls_weak_key | Certificate RSA 1024-bit, chữ ký SHA-256 | TLS_RSA_KEY_TOO_SMALL |
| tls_expired_cert | Certificate có validity đã hết hạn | TLS_CERT_EXPIRED |
| tls_hostname_mismatch | Certificate hostname khác SNI của client | TLS_CERT_HOSTNAME_MISMATCH |

Trong cấu hình hiện tại, RSA 1024-bit được gán **misconfiguration**.
Không chuyển nó thành attack chỉ vì phát hiện rule.

## Policy violation

| Scenario | Cấu hình/hành vi | Rule dự kiến |
|---|---|---|
| tls_weak_cipher | TLS 1.2 AES128-SHA: RSA key exchange, AES-128-CBC, HMAC-SHA1; certificate RSA 2048 | TLS_CIPHER_NOT_ALLOWED |
| ssh_weak_kex | diffie-hellman-group14-sha1 | SSH_KEX_WEAK |
| ssh_weak_cipher | aes128-cbc | SSH_CIPHER_WEAK |
| ssh_weak_mac | hmac-sha1 | SSH_MAC_WEAK |
| ssh_weak_host_key | ssh-rsa: RSA 2048 với chữ ký SHA-1 | SSH_HOST_KEY_SIGNATURE_WEAK |
| ssh_new_path | SSH đến backend trên đường truy cập không được baseline cho phép trong scenario | SSH_NEW_PATH |
| tls_unexpected_certificate | Đổi certificate ngoài lịch thay đổi được phép | Chưa gắn expected_rule cố định |

SSH fixture mặc định dùng curve25519-sha256, aes128-ctr, hmac-sha2-256
và ssh-ed25519; mỗi case yếu thay một thành phần. RSA/SHA-1 của ssh-rsa
khác RSA/SHA-2; không kết luận mọi khóa RSA đều yếu.

## Attack behavior được mô phỏng trong lab

| Scenario | Cách thực hiện | Quota tổng |
|---|---|---:|
| ssh_password_guessing | OpenSSH thử nhiều candidate sai vào một tài khoản lab | 180 |
| ssh_password_spraying | Một candidate sai cho ba tài khoản lab, lặp theo vòng | 120 |
| tls_beacon_jitter | HTTPS định kỳ với interval biến thiên 50–150% | 160 |
| tls_beacon_burst | Nhóm 3 HTTPS connection rồi nghỉ | 140 |
| tls_connection_burst | HTTPS burst hữu hạn, tối đa 2 request đồng thời | 120 |
| nmap_tcp_connect_scan | Nmap TCP connect vào 4443 và 4450–4455 của proxy | 160 |
| nmap_ssh_horizontal_scan | Nmap TCP connect port 22 của backend và DB | 120 |
| ssh_lateral_sequence | Key lab hợp lệ, ProxyJump đến backend rồi DB | 120 |
| tls_interception_fixture | Client→Nginx TLS CA lab riêng→TLS upstream | 80 |
| Tổng | | 1.200 |

Beacon/burst dùng TLS mạnh; guessing/spraying dùng SSH hiện đại do OpenSSH
thương lượng. Nmap không có crypto riêng. Interception dùng certificate
RSA 2048-bit/SHA-256 của CA lab khác, không phải phá mật mã.

Nhãn lấy từ manifest và bằng chứng thực thi có kiểm soát, không lấy từ alert.
Metadata mạng không chứng minh nội dung mật khẩu, số tài khoản hay ý định C2.
Spraying là fixture nén thời gian trong lab, không tái tạo chiến dịch kéo dài
nhiều ngày. Không có malware thật, không chứng minh DoS hay compromise thật.
Các attack mới chưa có expected_rule cố định; ground truth và rule detection
là hai thứ riêng cần đánh giá sau.

## Thời gian và cách thu

- Block 1: ít nhất 6.000 benign.
- Block 2–5: mỗi block ít nhất 5.250 benign, 225 misconfiguration,
  225 policy_violation và 300 attack_behavior.
- Block là nhóm quota theo thứ tự, không đồng nghĩa năm ngày lịch thật.
- Chạy lúc rảnh, ghi timestamp UTC thật; batch_1 không phải giờ giả.
- Mỗi round tối đa hai case bất thường; nghỉ 20–60 giây giữa các scenario,
  trong khi background vẫn chạy.
- Workload low/normal/busy thay đổi tốc độ truy cập và thời lượng SSH.
- Budget 90 phút/block/lần chạy là giới hạn mềm; round hiện tại hoàn tất trước.
  Tối đa 60 round/block; có thể phải resume hoặc tăng cap khi chưa đủ quota.
- Không pad/nhân bản record để bù số lượng. Session không khớp rõ manifest
  được quarantine, không tự gán benign.

## Sensor, nhãn và output

Zeek JSON: conn, ssl, x509, ssh, notice; weird dùng kiểm tra.
Extended metadata: IAT, vector kích thước/chiều gói giới hạn, TCP flags,
TLS extensions/signature scheme/ECH presence khi sensor quan sát được.
JA3/JA4/HASSH/JA4SSH phụ thuộc package, protocol và phiên bắt được.
TLS 1.3 certificate có thể không nhìn thấy; field thiếu để null, không giả lập.
Không lưu raw L7 payload, HTTP content, SSH username/command, credential,
decrypted TLS hoặc session secret trong dataset.

Chế độ `--simple-output`:

```text
data/lab_metadata/campaigns/<campaign_id>/
├── dataset.csv
├── scenario_manifest.csv
└── .internal/
```

Dataset chứa feature cùng `run_id`, `uid`, `scenario_id`,
`ground_truth_label`, `attack_family`, `ground_truth_source`,
`feature_version=lab-training-v2`, `label_version=lab-label-v1`.
Mapping manifest bằng `(run_id, scenario_id)`; label/provenance phải loại khỏi
input của model. CSV cập nhật sau round thành công, resume không thêm bản sao.
Schema, checksum, privacy validation và checkpoint được giữ trong `.internal`.

## Trạng thái mở rộng crypto

Yêu cầu thêm crypto vừa bắt đầu triển khai. `src/data_generation/generator.py`
có danh mục 16 profile mới và SSH fixture đã được sửa một phần.
**Các profile này chưa được thêm vào generation config hiện tại; TLS fixture
chưa tích hợp và chưa kiểm thử handshake đầy đủ.** Không tính chúng vào 23
scenario ở trên và không báo cáo là kết quả đã thu.

Các nhóm dự kiến gồm TLS 1.2 AES-256-GCM/ChaCha20/ECDSA, ba cipher TLS 1.3,
TLS CBC/static-RSA đối chứng, SSH ChaCha20/AES-GCM/AES-CTR với RSA-SHA2/ECDSA,
và SSH legacy group1/CBC/HMAC-MD5.

Tại thời điểm đối chiếu, thư mục campaigns chưa có campaign mới.
Chưa có số lượng thực thu, tỷ lệ thiếu feature hay metric ML để báo cáo.
