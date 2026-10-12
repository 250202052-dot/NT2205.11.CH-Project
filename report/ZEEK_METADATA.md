# Chạy Zeek cho Metadata-Only TLS/SSH

Cấu hình hiện tại đã được build và kiểm tra với Zeek **9.0.0** trong Docker lab. Chỉ ghi JSON metadata vào `data/lab_metadata/zeek/`. Có sáu stream được phép: `conn`, `ssl`, `x509`, `ssh`, `notice`, `weird`.

`f_L7(raw) = ∅` ở đây nghĩa là **không xuất hoặc lưu raw application payload**. Zeek vẫn đọc packet trong RAM để phân tích handshake TLS/SSH và chứng thư công khai. Không dump PCAP, không file extraction, không HTTP/DB content logger, không username/command/credential, không TLS keylog/decryption/session secret. Đây là policy của sensor/dataset; ứng dụng bán hàng vẫn có dữ liệu phục vụ hoạt động của chính nó, không được ingest vào dataset này.

## Các file

- `sensors/zeek/local.zeek`: load tối thiểu, JSON, analyzer allowlist, package options.
- `sensors/zeek/tls_policy.zeek`: TLS/certificate rules và certificate metadata.
- `sensors/zeek/ssh_policy.zeek`: SSH crypto rules và banner filtering.
- `sensors/zeek/policy_common.zeek`: notice evidence chung.
- `sensors/zeek/metadata_fields.zeek`: field allowlist, chặn stream khác, bridge JA4SSH → conn.log.
- `data/schemas/zeek_metadata_allowlist.json`: schema đối chiếu output.
- `data/schemas/validate_zeek_metadata.py`: validator trước feature extraction.
- `report/ZEEK_FEATURE_MAPPING.md`: nguồn gốc và giới hạn từng feature.

## 1. Package `zkg`

Dockerfile đã cài ba package, **không cần cài lại vào container đang chạy**. Sensor chỉ nối mạng monitor nên cài package ở bước build:

```sh
zkg install --force --skiptests --nosuggestions --version v0.18.8 https://github.com/FoxIO-LLC/ja4
zkg install --force --skiptests --nosuggestions --version 502cc6395811c54743b0561419d61900a6df3ff7 https://github.com/salesforce/ja3
zkg install --force --skiptests --nosuggestions --version 8280c8d1c70b6b8a419e9733230740e395d744fb https://github.com/corelight/hassh
```

`--skiptests` bỏ test upstream khi build; project có regression test riêng bên dưới. Corelight là fork HASSH được duy trì và chạy được trên Zeek 9. JA3 chỉ load `ja3` và `ja3s`, bỏ phần Intel integration thừa. JA4 bật JA4/JA4S/JA4SSH; tắt JA4H, JA4D, JA4L, JA4T, JA4TS, JA4X và raw fingerprints. HASSH tắt raw algorithm lists.

Không nâng package/image tự động: mapping và script gắn với các version này. JA4 client và những thành phần JA4+ có license upstream khác nhau; repository upstream là nơi đối chiếu license khi phân phối project.

## 2. Build/chạy từ PowerShell

Đứng tại `D:\NT2205.11.CH-Project`:

```powershell
docker compose build zeek
# Kiểm tra cấu hình không chiếm static IP của sensor đang chạy:
docker run --rm --network none --mount "type=bind,source=${PWD}\sensors\zeek,target=/config,readonly" --entrypoint zeek topic4-zeek -b -a /config/local.zeek
docker compose up -d --no-deps --force-recreate --wait zeek
docker compose exec -T zeek zeek --version
docker compose exec -T zeek zkg list
docker compose logs --tail 50 zeek
```

Entry point chạy:

```sh
zeek -b -C -i mirror0 /config/local.zeek
```

`-b` bỏ default site/L7 scripts; `-C` bỏ checksum verification do môi trường mirror/offload lab. Analyzer chỉ cho SSL, SSH, CONNSIZE. Native X509 analyzer được dùng để lấy certificate metadata, không extract file. SSH port 2222 được đăng ký cho bastion, SSH 22 vẫn có. Zeek quan sát frame đã tháo VXLAN tại mirror0.

JSON là **JSON Lines**, một object mỗi dòng. Không có traffic thì log tương ứng có thể chưa xuất hiện; không tạo record giả để điền đủ sáu file. Log rotate mỗi phút, tên dạng `ssl.*.log`; entrypoint giữ log lần chạy trước bằng đổi tên. Đọc cả `ssl*.log`, không chỉ `ssl.log`.

## 3. Sinh traffic và kiểm tra

Browser mở `https://localhost:8443` để xem UI. Để Zeek nhận traffic TLS qua router, dùng client lab/test; port publish Windows có thể đi đường khác và không qua mirror router.

```powershell
# Kiểm thử 6 profile certificate/TLS, khôi phục proxy ban đầu khi xong:
python tests/test_tls_profiles.py
# TLS modern/weak, SSH ProxyJump và flow Frontend → Backend → DB:
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_lab.ps1
# Unit rules + kiểm tra field filtering + validator trên log thật:
python tests/test_zeek_metadata.py
python data/schemas/validate_zeek_metadata.py
# Join metadata đã qua validator thành snapshot CSV:
python src/features/build_sessions.py
```

`ExecutionPolicy Bypass` chỉ áp dụng process PowerShell kiểm thử trên, không sửa execution policy toàn máy. Test tạo client tạm thời rồi thu dọn; vẫn một sensor và một proxy. Regression test dùng fixture metadata trong container `--network none`; không lưu PCAP và không gửi attack ra ngoài lab.

Xem log bằng PowerShell:

```powershell
Get-ChildItem data/lab_metadata/zeek/*.log
Get-ChildItem data/lab_metadata/zeek/ssl*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object uid,version,cipher,handshake_status,cert_key_bits,cert_trust_status,ja3,ja4,policy_violations
Get-ChildItem data/lab_metadata/zeek/ssh*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object uid,kex_alg,cipher_alg,mac_effective,host_key_alg,hassh,hasshServer,policy_violations
Get-ChildItem data/lab_metadata/zeek/notice*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object uid,note,rule_id,observed_metadata
```

`weird.log` ghi protocol anomaly, không phải mọi kết nối đều có. Fixture trong regression test kiểm tra stream này và xác nhận `addl` bị loại. Một warning malformed hoặc packet loss không tự động là attack.

## 4. Rule và trust trong lab

TLS chỉ cho TLS 1.2/1.3 và ciphers ECDHE+AEAD/TLS1.3 AEAD trong allowlist. Không đạt allowlist → policy violation. RSA dưới 2048, EC dưới 256, DSA, signature MD5/SHA1, cert expired/not-yet-valid, SNI mismatch và untrusted chain đều được kiểm tra riêng. Rule không coi thiếu field là yếu. TLS cipher không nằm allowlist có nghĩa là không đạt policy lab, không tự khẳng định có khai thác thành công.

SSH phát hiện SSHv1, legacy SHA1 DH KEX, CBC/RC4/3DES/Blowfish/CAST/none, MAC MD5/SHA1/UMAC64/none khi có hiệu lực, DSA hoặc `ssh-rsa` SHA1 host signature. `rsa-sha2-256/512` không bị đánh dấu chỉ vì tên RSA. AEAD không bị cảnh báo do MAC riêng advertised. Trường hai hướng mixed cipher được đánh giá bảo thủ; nếu cần loại false positive tuyệt đối ở trường hợp này, bổ sung normalization từng hướng.

Notice chỉ ghi alert/evidence, **không tự block hoặc thực hiện response**. Rule Engine/agent phía sau cần policy guard riêng.

Modern cert lab hiện là self-signed: validator Mozilla sẽ báo `self signed certificate`; đây là trust finding, chưa đủ để gắn nhãn attack. Có thể pin **public fingerprint**, không đưa private key/cert volume của proxy vào sensor. Lấy fingerprint:

```powershell
docker compose exec -T proxy openssl x509 -in /etc/nginx/tls/modern/server.crt -noout -fingerprint -sha256
```

Bỏ dấu `:`, chuyển thành hex chữ thường, rồi thêm vào cuối `local.zeek`:

```zeek
# Thay bằng fingerprint cert modern thực tế của lab, đủ 64 ký tự hex:
redef MetadataTLS::trusted_leaf_fingerprints += { "YOUR_64_CHAR_LOWERCASE_SHA256" };
```

Sau sửa script, kiểm tra cú pháp rồi restart sensor. Pin không bỏ qua expiry/hostname/key-size/signature. Native `SSL::Invalid_Server_Cert` vẫn có thể xuất hiện vì chain không thuộc Mozilla; custom `cert_trust_status=pinned_leaf` thể hiện trust policy lab riêng. Cấu hình mặc định chưa pin cert nào. Fingerprint đã biết của cert khác/pin không khớp cần correlation với baseline nếu muốn phát hiện thay đổi identity; không mặc định mỗi cert mới là MITM.

## 5. Missing data và dữ liệu cũ

- TLS 1.3 mã hóa certificate và một phần handshake; resumed TLS có thể không gửi cert. Khi đó giữ missing/certificate_visible=false, không giải mã để điền dữ liệu.
- `ssh.auth_success/auth_attempts` chỉ là inference từ packet size, không ground truth.
- JA4SSH được tính ở cuối connection/cửa sổ; session chưa kết thúc có thể chưa có conn record.
- Đồng hồ sensor cần đúng khi live capture. Khi đọc PCAP được cấp từ nguồn khác, thời gian rule là thời gian trace; project không tạo PCAP riêng.
- Log trước khi áp dụng cấu hình này được giữ tại `data/lab_metadata/zeek/archive/pre_metadata_v1_*`; không đưa vào dataset mới. Feature builder/validator mặc định chỉ đọc log ngay trong thư mục gốc, không đọc archive/edge/internal.
- Validator kiểm tra stream/field/banner/hash shape, không thể chứng minh tính đúng của mọi metadata value hoặc thay thế review script khi nâng version. Regression test chứng minh các field raw/free text tiêu biểu bị loại.

Xem mapping đầy đủ tại [ZEEK_FEATURE_MAPPING.md](ZEEK_FEATURE_MAPPING.md). Nguồn chính: [Zeek logging framework](https://docs.zeek.org/en/lts/scripts/base/frameworks/logging/main.zeek.html), [JA4 v0.18.8](https://github.com/FoxIO-LLC/ja4/tree/v0.18.8/zeek), [Corelight HASSH](https://github.com/corelight/hassh).
