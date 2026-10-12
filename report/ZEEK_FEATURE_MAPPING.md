# Mapping Zeek → feature của project

Áp dụng cho **Zeek 9.0.0**, image và package được pin trong `docker/zeek/Dockerfile`. Đây là mapping field thực sự được phép xuất, không phải danh sách tất cả field Zeek có thể thu.

Ý nghĩa nguồn gốc:

- **native**: Zeek có sẵn field khi load script tương ứng.
- **custom script**: script của project thêm field hoặc lọc giá trị.
- **package**: cần package `zkg`; không thuộc Zeek mặc định.
- **derived**: tính toán/join từ metadata đã thu; không đọc raw payload.
- **unavailable**: không có trong cấu hình này hoặc không quan sát được; để thiếu, không thay bằng 0/normal.

## Flow, thời gian và correlation

| Feature | Log.field | Nguồn gốc | Ý nghĩa/giới hạn |
|---|---|---|---|
| Session key | `conn.uid`, `ssl.uid`, `ssh.uid`, `notice.uid`, `weird.uid` | native | UID nối log của cùng một connection; một số notice/weird không gắn connection có thể thiếu UID. |
| Timestamp | `*.ts` | native | Unix timestamp của sự kiện; SSL/SSH thường là lúc bắt đầu connection, X.509 là thời điểm phân tích cert. |
| 5-tuple | `conn.id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto` | native | Vai trò orig/resp; giữ IP cho correlation. IP vẫn là định danh nhạy cảm: pseudonymize khi xuất dataset ra ngoài lab. |
| IP protocol | `conn.ip_proto` | native | Số protocol IP. |
| Duration | `conn.duration` | native | Giây; có thể thiếu ở flow chưa đủ dữ liệu. |
| Bytes | `conn.orig_bytes`, `resp_bytes` | native | Số byte payload vận chuyển theo hướng; **chỉ số đếm**, không lưu nội dung. |
| Packet/volume | `conn.orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes` | native | Thống kê CONNSIZE; được bật dù các analyzer L7 bị tắt. |
| State/history/loss | `conn.conn_state`, `history`, `missed_bytes` | native | Kiểm soát chất lượng capture; thiếu handshake có thể do mất gói. |
| Local direction | `conn.local_orig`, `local_resp` | native | Dựa trên `Site::local_nets`. |
| Service | `conn.service` | native | Chỉ analyzer được cho phép mới nhận diện; HTTP/DB service có thể thiếu, nhưng flow vẫn có. Không đoán TLS chỉ từ port. |
| Cert edge | `ssl.cert_chain_fps[]` → `x509.fingerprint` | native + derived join | Mảng fingerprint có thứ tự, phần tử 0 là leaf. `x509.log` không có UID. X509 cache làm cert không xuất lại mỗi session. |
| Client certificate edge | `ssl.client_cert_chain_fps[]` | native | Khi cert phía client nhìn thấy được; không phải định danh username. |
| Rule evidence | `notice.note`, `rule_id`, `policy_version`, `observed_metadata`, `actions` | native + custom script | `rule_id` và evidence chỉ có ở rule project; native notice có thể thiếu. Correlate bằng UID. Không xuất msg/sub/file_desc. |
| Protocol anomaly | `weird.name`, `notice`, `source` + UID/tuple | native | Mã anomaly; không xuất `addl`, vì có thể chứa dữ liệu do peer gửi. |
| Rates/windows/graph | các tuple, timestamp, packet/byte count, UID, cert/hostkey hashes | derived | Cần window aggregator hoặc graph builder; `build_sessions.py` mới làm join một dòng/UID. |
| Packet sequence / exact interarrival times | không có | unavailable | Sáu log hiện tại không chứa chuỗi timestamp/size từng gói. Không tuyên bố đã có input sequence DL; cần custom bounded metadata collector nếu chọn mô hình này. |

## TLS

| Feature | Log.field | Nguồn gốc | Ý nghĩa/giới hạn |
|---|---|---|---|
| TLS version | `ssl.version` | native | Tên Zeek: `TLSv12`, `TLSv13`, v.v. |
| Negotiated cipher | `ssl.cipher` | native | Tên IANA; rule dùng allowlist. |
| Curve | `ssl.curve` | native | Khi handshake cho phép quan sát. |
| Handshake evidence | `ssl.established`, `last_alert`, `ssl_history`, `resumed` | native | Trạng thái quan sát của Zeek, không chứng minh client đã tin cert hoặc application login thành công. |
| Handshake status | `ssl.handshake_status` | custom script | `established`, `alerted`, `not_established_or_incomplete`. Trạng thái cuối không đồng nghĩa attack. |
| Cert visibility | `ssl.certificate_visible` | custom script | False = chưa nhìn thấy cert; không đồng nghĩa cert hợp lệ hoặc bất hợp lệ. |
| TLS client JA3 | `ssl.ja3` | package: Salesforce JA3 | MD5 fingerprint ClientHello; thiếu khi không bắt được hello. Hash không phải định danh chắc chắn. |
| TLS server JA3S | `ssl.ja3s` | package: Salesforce JA3 | ServerHello fingerprint. |
| TLS client JA4 | `ssl.ja4` | package: FoxIO JA4 v0.18.8 | Fingerprint đã tổng hợp. Không xuất raw component strings. |
| TLS server JA4S | `ssl.ja4s` | package: FoxIO JA4 v0.18.8 | Chỉ là handshake metadata; không bật JA4H/HTTP. |
| TLS policy violations | `ssl.policy_violations`, `policy_version` | custom script | Kết quả policy, dùng cho Rule Engine/evidence; tránh đưa vào ML để dự đoán chính nhãn này gây leakage. |
| SNI/certificate match | `ssl.sni_matches_cert` | native | Boolean; raw SNI không xuất. Thiếu nếu không có SNI hoặc không nhìn thấy cert. |
| Certificate chain status | `ssl.validation_status` | native policy script | Cần `policy/protocols/ssl/validate-certs` và Mozilla CA list. Có cache; không kiểm tra OCSP/CRL online trong cấu hình này. |
| Trust interpretation | `ssl.cert_trust_status` | custom script | `valid_chain`, `pinned_leaf`, `untrusted`; pin chỉ cho leaf lab được cấu hình rõ ràng. |
| Leaf metadata copied to UID | `ssl.cert_fingerprint`, `cert_spki_sha256`, `cert_key_type`, `cert_key_bits`, `cert_sig_alg`, `cert_not_valid_before`, `cert_not_valid_after`, `issuer_name_sha256`, `cert_chain_len` | custom script | Copy từ native X509/chain và custom hash; giúp rule theo connection, không cần join bên ngoài. |
| Certificate time status | `ssl.cert_validity_status` | custom script | `valid`, `expired`, `not_yet_valid`; so sánh với `network_time()` tại session, không dùng đồng hồ lúc đọc lại log. |
| Raw SNI, ALPN, issuer DN, subject DN | không xuất | native tồn tại, cố ý loại | JA4 có token ALPN chuẩn hóa nhưng không lưu raw ALPN/SNI. Issuer giữ dưới dạng hash bên dưới. |
| TLS 1.3/resumed certificate | thường không có `cert_*`/X509 | unavailable trên session không nhìn thấy cert | TLS 1.3 mã hóa Certificate; resumed TLS 1.2 có thể không gửi cert. Không bật decryption để điền thiếu. |
| TLS session secret, decrypted content, HTTP content | không có | unavailable / prohibited | Không keylog, không TLS decryption, không HTTP analyzer/content logger. |

## X.509

| Feature | Log.field | Nguồn gốc | Ý nghĩa/giới hạn |
|---|---|---|---|
| Cert fingerprint | `x509.fingerprint` | native | SHA-256 của DER certificate trong image này, 64 ký tự hex. |
| Certificate version | `x509.certificate.version` | native | Không nhầm với TLS protocol version. |
| Validity start/end | `x509.certificate.not_valid_before`, `not_valid_after` | native | Unix timestamp. |
| Lifetime / remaining days | `(after-before)/86400`, `(after-conn.ts)/86400` | derived | `build_sessions.py`: `cert_validity_days`, `cert_remaining_days_at_session`. |
| Public-key algorithm | `x509.certificate.key_alg` | native | Algorithm identifier. |
| Key type/size/curve | `x509.certificate.key_type`, `key_length`, `curve` | native | Bit count khi Zeek/OpenSSL hỗ trợ; RSA bit count không có cùng ý nghĩa bảo mật với EC bit count. |
| Cert signature | `x509.certificate.sig_alg` | native | Rule phát hiện MD5/SHA1 signature. Không phải TLS cipher hash. |
| Host/client cert | `x509.host_cert`, `client_cert` | native | Vai trò certificate; có thể optional. |
| SPKI SHA256 | `x509.spki_sha256` | custom script, native BIF | `bytestring_to_hexstr(x509_spki_hash(cert_ref, 4))`; SHA256 của DER SPKI, hex. **Không phải native log field**. Hash type 4 = SHA256. |
| Issuer name | `x509.issuer_name_sha256` | custom script, native BIF | SHA256 DER issuer name qua `x509_issuer_name_hash(ref, 4)`. Có issuer identity để correlation nhưng không lưu raw DN. |
| Subject name | `x509.subject_name_sha256` | custom script, native BIF | SHA256 DER subject name qua `x509_subject_name_hash(ref, 4)`. |
| Self-issued indicator | `x509.issuer_class` | custom script | So sánh issuer/subject: `self_issued` hoặc `ca_issued`. **Không chứng minh self-signature hoặc trusted CA**; xem validation/pin riêng. |
| SAN shape | `x509.san_dns_count`, `san_ip_count` | custom script | Đếm SAN từ event native, không lưu hostname/IP SAN thô. |
| Raw certificate/PEM/DER file | không có | prohibited | Cert được phân tích trong RAM để lấy metadata, không attach extraction analyzer và không ghi cert file. |
| OCSP/CRL revocation / key private | không có | unavailable / prohibited | Không tuyên bố cert chưa bị thu hồi; không thu private key. |

## SSH

| Feature | Log.field | Nguồn gốc | Ý nghĩa/giới hạn |
|---|---|---|---|
| Protocol version | `ssh.version` | native | Count, thường 2. |
| Software version | `ssh.client`, `server` | native + custom filtering | Chỉ token `SSH-2.0-OpenSSH_...`; bỏ banner comments/OS details. Không parse được → `unparsed_ssh_banner`. |
| Negotiated KEX | `ssh.kex_alg` | native | Thu từ KEXINIT rõ trước mã hóa; thiếu nếu capture giữa session. |
| Cipher / MAC | `ssh.cipher_alg`, `mac_alg` | native | Có thể biểu diễn hai hướng nếu khác nhau. MAC advertised không có hiệu lực riêng khi cipher AEAD. |
| Effective MAC | `ssh.mac_effective` | custom script | `aead_implicit` nếu AEAD; nếu không lấy MAC negotiated. Với cipher khác nhau theo hướng, cần đánh giá từng hướng để phân tích chính xác; rule hiện tại đánh giá bảo thủ khi có non-AEAD. |
| Compression | `ssh.compression_alg` | native | Negotiated metadata; không giải nén để đọc payload. |
| Host-key algorithm | `ssh.host_key_alg` | native | `ssh-rsa` = SHA1 signature policy violation; `rsa-sha2-*` không bị kết luận yếu chỉ vì là RSA. |
| Host-key fingerprint | `ssh.host_key_fingerprint` | native Zeek 9 | Chuỗi SHA256 native; **không đảm bảo native trên mọi Zeek cũ**. Không parse payload để lấy thêm key length. |
| SSH host-key bit length | không có | unavailable trong cấu hình này | Không suy đoán bit count từ tên `ssh-rsa`. Cần custom parsing metadata host key nếu bổ sung sau. |
| HASSH client/server | `ssh.hassh`, `hasshServer`, `hasshVersion` | package: Corelight HASSH | Hash từ danh sách KEX/cipher/MAC/compression; đã tắt output raw algorithm lists. |
| JA4SSH | `conn.ja4ssh` | package FoxIO + custom bridge | Package tính packet size/direction/count fingerprint theo cửa sổ 200 gói; bridge copy **cửa sổ cuối**, kể cả cửa sổ ngắn lúc connection kết thúc, vào conn.log. Không phải fingerprint ClientHello/SSH software. Không xuất ja4ssh.log riêng. |
| Authentication inference | `ssh.auth_success`, `auth_attempts` | native, derived inference trong analyzer | Suy luận từ kích thước gói mã hóa; không phải log auth thật. Không dùng làm ground truth đăng nhập thành công/brute force. |
| Direction | `ssh.direction` | native | Khi Zeek suy ra được direction. |
| SSH crypto violations | `ssh.policy_violations`, `policy_version` | custom script | KEX SHA1 legacy, CBC/RC4/3DES..., weak non-AEAD MAC, SSHv1, DSA/SHA1 host signature. |
| Username, command, credential, file content | không có | unavailable / prohibited | Không giải mã SSH; không kết hợp auth/application logs có username/command trong dataset metadata-only. |

## Cách dùng cho project

1. Chạy privacy validator trước khi đưa dữ liệu vào pipeline.
2. Rule Engine đọc `ssl/ssh.policy_violations` và `notice.rule_id` để có evidence.
3. Tabular/anomaly model lấy byte/packet/duration và crypto metadata; missing mask cho feature không quan sát được. Không dùng policy result hoặc scenario labels làm input để dự đoán cùng nhãn.
4. Correlation nối UID, endpoint và fingerprint/SPKI/host-key; join `notice` có thể là quan hệ 1-n, không chỉ lấy notice cuối.
5. Sequence/graph DL cần thiết kế window/graph và split riêng. Cấu hình sensor hiện tại cung cấp dữ liệu nền, chưa tự tạo dataset sequence/graph hoặc label attack.

Nguồn đối chiếu: [Zeek SSH log](https://docs.zeek.org/en/current/reference/logs/ssh.html), [Zeek 9 X509 BIF](https://github.com/zeek/zeek/blob/v9.0.0/src/file_analysis/analyzer/x509/functions.bif), [JA4 Zeek](https://github.com/FoxIO-LLC/ja4/tree/v0.18.8/zeek), [JA3](https://github.com/salesforce/ja3), [Corelight HASSH](https://github.com/corelight/hassh).
# Metadata packet và TLS extension bổ sung

Profile opt-in `ZEEK_EXTENDED_METADATA=true` thêm `packet_metadata.log` và `tls_extensions.log`. Các field mới là **custom script** dùng native packet-header/TLS events, không phải field có sẵn trong conn.log/ssl.log. Join UID vào companion `extended/metadata_extensions.csv`, giữ schema baseline. Mapping chi tiết, đơn vị và giới hạn xem [EXTENDED_METADATA.md](EXTENDED_METADATA.md).

| Feature | Log/field | Availability |
|---|---|---|
| IAT mean/std từng chiều | packet_metadata.orig/resp_iat_mean/std | custom, thống kê sensor, thiếu khi không có interval |
| Packet size/direction sequence | packet_metadata.pkt_size_vector/pkt_direction_vector | custom, 32 packet đầu mặc định |
| TCP flag counts từng chiều | packet_metadata.tcp_flags_orig/resp | custom, 8 flags, không phải retransmission |
| TLS extension codes | tls_extensions.client/server_extensions | custom từ ssl_extension, không raw value |
| ECH extension presence | tls_extensions.ech_observed | custom, không chứng minh accepted; null nếu thiếu Hello |
| Advertised client signature schemes | tls_extensions.client_signature_schemes | custom từ ssl_extension_signature_algorithm |
| Observed server handshake signature scheme | tls_extensions.server_signature_scheme | custom từ ssl_server_signature; không có nếu event không quan sát được |

