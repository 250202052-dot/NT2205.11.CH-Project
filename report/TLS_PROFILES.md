# Thử certificate/TLS trên một Reverse Proxy

Theo mục 13.3 của file Word, lab cần thử TLS weak-policy và certificate unexpected/self-signed/expired. Các profile dưới tạo những tình huống này trên **cùng một Proxy**, không thêm container. Web bán hàng và DB không thay đổi.

## 1. Các profile hiện có

| TLS_PROFILE | Certificate | TLS negotiation | Điều cần kiểm tra |
| --- | --- | --- | --- |
| `modern` | RSA 2048, SHA-256, SAN `proxy.topic4.lab`, 30 ngày | TLS 1.2/1.3; TLS 1.2 dùng ECDHE + AES-GCM | Baseline khi client tin certificate đã cấp |
| `weak` | RSA 1024 | TLS 1.2, RSA key exchange + AES-CBC/SHA-1 | Vi phạm crypto policy; có cả key yếu và cipher yếu |
| `weak-cert` | RSA 1024, SHA-256 | TLS 1.2, ECDHE + AES-GCM; SECLEVEL=0 để Nginx phục vụ key yếu | Tách vấn đề key certificate khỏi RSA/CBC cipher của `weak` |
| `expired-cert` | RSA 2048, hiệu lực 01/01/2000–01/01/2001 | Giữ policy modern | Client từ chối vì hết hạn |
| `wrong-host` | RSA 2048, SAN `other.topic4.lab` | Giữ policy modern | Client yêu cầu `proxy.topic4.lab` bị hostname mismatch |
| `replaced-cert` | RSA 2048, SAN đúng, key/certificate khác baseline | Giữ policy modern | Client chỉ tin cert modern sẽ từ chối cert self-signed mới |

**Tất cả là certificate tự ký của lab.** `modern` chỉ là baseline thuật toán và certificate được client chủ động tin/pin, không phải certificate công khai được Windows tự tin. Cảnh báo tại `https://localhost:8443` còn có hostname `localhost` khác SAN. Vì vậy test certificate dùng tên `proxy.topic4.lab` qua `--resolve`, để không nhầm lỗi hostname với lỗi cần nghiên cứu.

Đổi certificate không tự chứng minh MitM. `replaced-cert` chỉ tạo identity/trust-change fixture; chưa có interception/route manifest. Đổi key có thể là bảo trì hợp lệ, cần một scenario benign renewal riêng và bằng chứng phê duyệt trong manifest.

## 2. Chọn một profile

Trong PowerShell:

```powershell
cd D:\NT2205.11.CH-Project
$env:TLS_PROFILE = 'expired-cert'
docker compose up -d --no-deps --wait proxy
```

Thay `expired-cert` bằng tên khác trong bảng. Image đã được build với các profile; các lần chuyển không cần rebuild.

Kiểm tra profile đang chạy:

```powershell
docker compose exec -T proxy printenv TLS_PROFILE
```

Certificate/key của từng profile nằm trong volume `proxy-tls`, ở `/etc/nginx/tls/<profile>/`. Chuyển qua lại không tự tạo key mới, nhờ đó fingerprint ổn định cho từng fixture. Không xóa volume để đổi profile. Modern/weak/replaced/weak-cert/wrong-host có hạn 30 ngày từ lúc sinh; không có auto-renew nên dữ liệu drift/renewal cần kịch bản rõ ràng.

## 3. Xem certificate hết hạn

```powershell
docker compose exec -T proxy openssl x509 -in /etc/nginx/tls/expired-cert/server.crt -noout -subject -issuer -dates -fingerprint -sha256
```

Kết quả cần thấy: `notAfter` là năm **2001**. Profile dùng OpenSSL CA để đặt ngày lịch sử, không sửa đồng hồ Windows/container.

Tạo client tạm:

```powershell
docker compose --profile test up -d client
```

Cấp **public certificate** expired cho client để thử riêng lỗi thời hạn (không copy private key):

```powershell
$cert = docker compose exec -T proxy cat /etc/nginx/tls/expired-cert/server.crt
$cert | docker compose exec -T client sh -c 'cat > /tmp/profile.crt'
docker compose exec -T client curl -fsS --max-time 10 --tls-max 1.2 --cacert /tmp/profile.crt --resolve proxy.topic4.lab:443:172.30.20.10 https://proxy.topic4.docker/api/status
$LASTEXITCODE
```

**Đạt:** curl báo certificate expired, mã thoát `60`. Không dùng `-k` trong bước kiểm tra từ chối này.

Sau đó tạo một phiên TLS hoàn chỉnh để Zeek thu metadata, bằng client test cố ý bỏ kiểm tra cert:

```powershell
docker compose exec -T client curl -fsSk --max-time 10 --tls-max 1.2 --ciphers 'ALL:@SECLEVEL=0' https://172.30.20.10/api/status
```

**Đạt:** JSON có `db_result: 1`. Kết quả này chỉ chứng minh service vẫn phục vụ khi test client bỏ qua kiểm tra; không chứng minh certificate hợp lệ. Client Windows vào Proxy trực tiếp qua published port; client lab đi qua Router mirror.

## 4. Test tất cả profile tự động

```powershell
python tests/test_tls_profiles.py
```

Script lần lượt đổi 6 profile trên một proxy, kiểm tra strict client từ chối đúng lỗi, sau đó dùng permissive test client tạo phiên hoàn chỉnh. Nó ép TLS 1.2 để sensor thụ động nhìn thấy certificate; TLS 1.3 bảo vệ thông điệp certificate nên không được giả định Zeek luôn đọc được X.509.

Script kiểm tra log Zeek mới trong đúng cửa sổ thời gian và đúng fingerprint, key RSA-1024, cert expired và cipher RSA/CBC hoặc ECDHE/GCM. Nó restart Zeek trước test để xóa cache certificate trong bộ nhớ, và sau test để flush logs, gây gián đoạn capture ngắn; chỉ chạy khi nghiệm thu lab. Khi thu liên tục, một certificate có thể chỉ xuất hiện một lần trong x509.log; ghép phiên mới với certificate đã biết bằng fingerprint, không đòi mỗi phiên có một bản ghi x509 mới.

Manifest xuất tại `data/manifests/tls_profiles_<timestamp>.csv`: thời gian, profile, điều kiện dự kiến, certificate/SPKI SHA-256 và kết quả strict client. Không chứa private key, body API hay credentials. Đây là **manifest thử nghiệm**, chưa phải dataset training đã gắn attack labels. Khi ghép labels cần đối chiếu UID/time/role và policy; không đưa tên profile vào feature để tránh label leakage.

Cuối script khôi phục profile ban đầu và chỉ gỡ client nếu script đã tạo nó. Nếu script lỗi, đọc lỗi; manifest có thể chỉ chứa một phần profile. `CLIENT_PASS` nghĩa là bước kiểm tra client đạt, `PASS` nghĩa là đã xác nhận thêm metadata Zeek; manifest một phần chưa chứng minh cả bộ đạt.

## 5. Trả về Web bình thường

```powershell
$env:TLS_PROFILE = 'modern'
docker compose up -d --no-deps --wait proxy
docker compose rm -s -f client
```

Mở lại `https://localhost:8443/`. `healthy` của Proxy chỉ kiểm tra dịch vụ còn hoạt động, không kiểm tra certificate an toàn; các fixture cố ý lỗi vẫn phải healthy để thử nghiệm.

Code: `docker/proxy/create-certificate.sh` sinh cert; `entrypoint.sh` chọn cert/cấu hình Nginx. Nginx template nằm trong `modern.conf` và `weak.conf`. Cách đặt thời hạn certificate dựa trên [OpenSSL CA documentation](https://docs.openssl.org/3.6/man1/openssl-ca/).
