# Thu metadata packet và TLS extension

Phần mở rộng giúp lấy IAT, chuỗi kích thước packet, TCP flags, TLS extension codes và signature schemes. Không cần NetFlow, không thêm container chính. Dùng Zeek 9 trong sensor hiện tại và traffic mirror sau khi giải đóng gói VXLAN tại `mirror0`.

Mặc định `ZEEK_EXTENDED_METADATA=false` để giữ campaign baseline. Chỉ bật trước phiên thu mới hoặc sau khi dừng campaign và chờ cleanup. Không sửa dataset đã thu để giả lập field mới.

## 1. Các file mới

| File | Chức năng |
|---|---|
| `sensors/zeek/packet_metadata.zeek` | Tính packet header metadata trong bộ nhớ |
| `sensors/zeek/tls_extensions.zeek` | Giữ TLS extension codes và thuật toán, bỏ raw values |
| `sensors/zeek/extended_profile.zeek` | Load hai module và mở allowlist cho hai log mới |
| `data/schemas/validate_extended_metadata.py` | Kiểm tra loại dữ liệu/vector/range và missingness |
| `src/features/extended_metadata.py` | Join UID và xuất bảng bổ sung có schema/version/checksum |
| `scripts/dataset_tools.py extended` | Export hoặc validate companion của một round |
| `tests/test_extended_metadata.py` | Fixture events, privacy, vector bounds và CSV/Parquet |

Validator log chính đã nhận hai stream mới. Bộ snapshot thu hai log theo UID trong conn.log. Labeler và campaign aggregator xuất companion khi có metadata mới; dataset baseline và ablation hiện tại giữ nguyên danh sách cột/version.

## 2. Định nghĩa field

| Field/log | Nguồn | Định nghĩa và giới hạn |
|---|---|---|
| `orig_iat_mean/std`, `resp_iat_mean/std` / packet_metadata | Custom `new_packet` | Khoảng giữa packet cùng chiều, đơn vị giây; std population; thiếu nếu không có interval |
| `orig_iat_count`, `resp_iat_count` | Custom | Số interval dùng cho thống kê; packet đơn lẻ không có IAT |
| `pkt_size_vector` | IP header | 32 packet đầu mặc định, tối đa cấu hình 128; IPv4 total length, IPv6 payload length+40; không tính Ethernet/VXLAN |
| `pkt_direction_vector` | Header + connection | Cùng độ dài size vector; 0 originator, 1 responder; không mặc định originator luôn là client |
| `tcp_flags_orig/resp` | TCP header | 8 bộ đếm theo thứ tự FIN,SYN,RST,PSH,ACK,URG,ECE,CWR; một packet có thể tăng nhiều bộ đếm; không phải retransmission count |
| `sequence_truncated` | Custom | Tổng packet quan sát vượt sequence limit |
| `orig/resp_observed_packets` | Custom | Packet được event xử lý; không bảo đảm bằng toàn bộ packet gửi trên mạng |
| `unordered_timestamps` | Custom | Timestamp đi lùi so với mốc trước; bỏ interval âm, vẫn tính packet |
| `client_extensions`, `server_extensions` / tls_extensions | `ssl_extension` | Tập numeric extension codes theo phía gửi; không lưu raw `val`; không phải vector có thứ tự |
| `client_hello_observed`, `server_hello_observed` | TLS events | Sensor thấy Hello; không chứng minh toàn bộ connection capture đầy đủ |
| `ech_observed` | ClientHello extension presence | Có extension 65037; false chỉ khi thấy ClientHello mà không có code; nếu không thấy Hello thì null |
| `client_signature_schemes` | `ssl_extension_signature_algorithm` | Danh sách thuật toán được client quảng bá; numeric code = HashAlgorithm*256+SignatureAlgorithm |
| `server_signature_scheme` | `ssl_server_signature` | Thuật toán ký server handshake khi event có; không phải thuật toán ký certificate |

IAT là thời gian sensor quan sát, không phải đo trực tiếp tại endpoint. Không xuất packet timestamp sequence, TCP sequence/ACK number, raw payload, private key, client/server random, raw extension, ECH encapsulation hay signature bytes. Không giải mã TLS.

Các extension codes có thể là GREASE/unknown. `ech_observed=true` không chứng minh ECH thật sự được chấp nhận. TLS1.3 encrypted handshake có thể khiến `server_signature_scheme` không có; giữ null, không thay bằng certificate sigalg. Size vector chứa cả header-only ACK; không lọc chỉ data packets trong phiên bản này.

## 3. Bật khi bắt đầu phiên thu phù hợp

PowerShell, tại project-root. Nếu đang thu, nhấn Ctrl+C một lần và đợi cleanup trước:

```powershell
$env:ZEEK_EXTENDED_METADATA = 'true'
docker compose build zeek
docker compose up -d --no-deps --wait zeek
docker compose exec -T zeek printenv ZEEK_EXTENDED_METADATA
```

Giá trị phải là `true`. Image mới có entrypoint biết load extended profile và archive cả hai log mới trước restart. Chỉ `docker compose restart zeek` không cập nhật image/environment của container cũ. Có thể lưu biến trong `.env` để các phiên PowerShell sau dùng cùng profile; `.env.example` là mẫu.

Để thu đợt mới có đầy đủ metadata từ đầu, dùng campaign mới:

```powershell
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --mode compressed --campaign-id 20261009_extended_v1 --collect --parquet
```

Tên lưu cố định cho đợt extended mới là `20261009_extended_v1`:

```text
data/lab_metadata/campaigns/20261009_extended_v1/
├── checkpoint.json
└── dataset/
    ├── labeled_sessions.csv
    ├── labeled_sessions.parquet
    └── extended/metadata_extensions.csv (.parquet)

data/lab_metadata/custom/20261009_extended_v1_d<day>s<slot>r<round>/
data/manifests/custom/20261009_extended_v1_d<day>s<slot>r<round>/
```

Thư mục được tạo khi bắt đầu collection, không cần tự tạo trước. Nếu tên đã tồn tại, script từ chối tạo lại; không ghi đè. Khi nghỉ rồi tiếp tục, giữ extended profile bật và dùng:

```powershell
$env:ZEEK_EXTENDED_METADATA = 'true'
docker compose up -d --no-deps --wait zeek
.\.venv\Scripts\python.exe scripts/run_dataset_campaign.py --resume "data/lab_metadata/campaigns/20261009_extended_v1" --parquet
```

Không dùng lệnh tạo campaign mới nếu chỉ muốn tiếp tục campaign cũ. Nếu resume campaign cũ sau khi bật, report coverage sẽ có session cũ thiếu metadata. Không coi các session cũ đã thu đủ field mới; so sánh feature mở rộng phải chọn cohort có capture tương ứng và cùng split.

Tắt trước phiên baseline tiếp theo:

```powershell
$env:ZEEK_EXTENDED_METADATA = 'false'
docker compose up -d --no-deps --wait zeek
```

Đảm bảo `.env` không có giá trị ngược với lựa chọn. Không đổi profile trong round đang thu.

## 4. Log và output nằm ở đâu?

Sensor ghi `data/lab_metadata/zeek/packet_metadata*.log` và `tls_extensions*.log`. Một số log chỉ được ghi khi connection kết thúc/flush; không thấy ngay lập tức chưa đủ kết luận sensor lỗi.

Round mới snapshot chúng ở `data/lab_metadata/custom/<run_id>/zeek/`. Nếu có record mới, labeler xuất:

```text
<run_id>/
├── labeled_sessions.csv             # Baseline giữ nguyên
└── extended/
    ├── metadata_extensions.csv
    ├── metadata_extensions.parquet  # Khi bật Parquet
    ├── schema.json
    ├── privacy_validation.json
    └── checksums.json
```

Companion chỉ chứa ID và feature mở rộng. Join với baseline bằng `(run_id, uid)`, không join theo thứ tự dòng. Hai flag `packet_metadata_present`, `tls_extensions_present` mô tả coverage. Với SSH/HTTP/DB, không có TLS extension là bình thường.

Campaign aggregator tạo `dataset/extended/`, và companion tương ứng trong full_collection/context/splits khi có metadata mới. Nó giữ số session baseline; không tăng quota vì có thêm log. Chưa tự đưa các feature mới vào input của runner ablation-v1; cần feature config/preprocessing cho thí nghiệm mở rộng riêng, đặc biệt vector sequence.

## 5. Export và kiểm tra thủ công

Cho round đã hoàn thành có log snapshot, thay TEN_ROUND bằng tên thực:

```powershell
.\.venv\Scripts\python.exe scripts/dataset_tools.py extended --run "data/lab_metadata/custom/TEN_ROUND" --parquet
.\.venv\Scripts\python.exe scripts/dataset_tools.py extended --validate "data/lab_metadata/custom/TEN_ROUND/extended"
```

Lệnh thủ công không thay baseline; companion có checksum riêng. Không chạy lên round đang ghi. Nếu log cũ không có stream mới, export được bảng presence=false/null, không phục dựng thông tin packet.

Raw log vẫn dùng validator chính:

```powershell
.\.venv\Scripts\python.exe data/schemas/validate_zeek_metadata.py --logs "data/lab_metadata/zeek"
.\.venv\Scripts\python.exe tests/test_extended_metadata.py
```

`--dataset` của validator chính kiểm tra baseline, không tự duyệt `extended/`; dùng `--validate` ở trên cho companion.

## 6. Kết quả kiểm thử và bước còn lại

- Fixture Zeek: IAT mean/std, flags, tách chiều, unordered timestamps, TLS extension/ECH/scheme codes; raw sentinel không xuất vào log.
- Validator/companion: null khi không có Hello/metadata, sequence bounds, rejection vector chứa text, CSV/Parquet khớp.
- Capture thử cô lập 15 giây trên mirror: 153 packet-metadata sessions, 21 TLS-extension sessions, validator đạt; 2.421 packet nhận, không ghi nhận drop trong lượt thử đó. Đây là pilot kiểm tra chức năng, không chứng minh performance của campaign dài.

Sensor chính không bị restart bởi kiểm thử. Cần bật profile bằng quy trình mục 3 trước khi thu phiên mở rộng chính thức. Tiếp theo là xem coverage và overhead trên pilot dài hơn, rồi chọn cohort/feature version cho ML. Scheme tokenization, 5-minute baseline và ground-truth annotation vẫn là module riêng, chưa được hoàn thiện chỉ bằng hai log mới.
