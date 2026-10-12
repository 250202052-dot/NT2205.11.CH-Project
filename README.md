# Topic 4 — Docker lab tối giản

Các file thí nghiệm đang dùng và phần cần giữ:
[experiments/README.md](experiments/README.md).

## Đọc code theo thứ tự nào?

`scripts/` chỉ chứa các lệnh chạy. Code nội bộ thu dữ liệu nằm trong
`src/data_generation/`, code xử lý feature nằm trong `src/features/`.

| Lệnh chính | Vai trò |
|---|---|
| `scripts/run_dataset_campaign.py` | Thu hoặc resume dataset |
| `scripts/audit_custom_dataset.py` | Kiểm tra dataset |
| `scripts/prepare_custom_ablation.py` | Chuẩn bị subset và split |
| `scripts/run_model_baselines.py` | Lệnh train RF/XGBoost/LightGBM, gọi `src/models/baselines.py` |
| `scripts/run_ablation.py` | A/B/C × RF/XGBoost/LightGBM, dùng chung preprocessing/train/CV của baseline |
| `scripts/dataset_tools.py` | Công cụ export thủ công; bình thường không cần chạy |
| `scripts/start-lab.ps1`, `scripts/trust-lab-hosts.ps1` | Khởi động lab và chuẩn bị SSH trust |

Code hỗ trợ gồm 5 module: `generator.py` điều phối một round và khai báo profile,
`runtime.py` gọi Docker và hiển thị tiến độ, `scenarios.py` thực hiện scenario
TLS/SSH, `attacks.py` thực hiện các hành vi attack trong lab, `output.py` công bố CSV.
Hai công cụ export cũ được thay bằng:

```powershell
.\.venv\Scripts\python.exe scripts/dataset_tools.py training --dataset <campaign_dataset_directory>
.\.venv\Scripts\python.exe scripts/dataset_tools.py extended --run <completed_round_directory>
.\.venv\Scripts\python.exe scripts/dataset_tools.py extended --validate <extended_directory>
```

## So sánh baseline Random Forest / XGBoost / LightGBM

Dùng cùng subset custom 30.000 session và split theo thời gian đã kiểm tra.
Mặc định dùng feature Fused, seed 42, ba fold CV theo thời gian trên train;
final test giữ riêng. Tham số cố định ở đầu
`src/models/baselines.py`, không cần JSON cấu hình:

```powershell
.\.venv\Scripts\python.exe -m pip install -r experiments/requirements-baselines.txt
.\.venv\Scripts\python.exe scripts/run_model_baselines.py --train
```

Thêm `--groups A B C` để chạy cả ba nhóm feature. Output tại
`experiments/results/model_baselines/`. Hướng dẫn dễ đọc:
[MODEL_BASELINES.md](report/MODEL_BASELINES.md).

## Kiểm tra dataset đã thu và chạy A/B/C

Code mới đọc CSV `lab-training-v2` của campaign `custom_data_v1`. Audit dữ liệu,
chuẩn bị subset 30.000 session và chạy ba thí nghiệm L3/L4, TLS/SSH, Fused:

```powershell
.\.venv\Scripts\python.exe scripts/audit_custom_dataset.py
.\.venv\Scripts\python.exe scripts/prepare_custom_ablation.py
.\.venv\Scripts\python.exe scripts/run_ablation.py --train
```

Subset đã chuẩn bị thì không cần chạy lại bước prepare. Các lệnh và cách đọc
report nằm trong [CUSTOM_DATASET_AUDIT_ABLATION.md](report/CUSTOM_DATASET_AUDIT_ABLATION.md).

## Custom dataset có thêm attack — profile v3

Mặc định campaign mới dùng `experiments/campaign_attack_v3.json`: mục tiêu tối thiểu
30.000 session gồm 27.000 benign (90%), 900 misconfiguration (3%), 900 policy
violation (3%) và 1.200 attack (4%). Giữ thêm benign thật đã thu nên tổng có thể
lớn hơn 30.000; tỷ lệ thực tế được ghi trong summary. Mỗi round tối đa hai case
bất thường, nghỉ 20–60 giây với background vẫn chạy. Đây là thiết kế lab,
không phải tỷ lệ đo được ngoài doanh nghiệp. Quota attack chia chín nhóm, dùng OpenSSH password auth, Nmap,
curl TLS timing/burst, ProxyJump và Nginx interception fixture trong lab.
Timestamp thật, không hẹn giờ; resume giữ config cũ.

Hướng dẫn build client, smoke, chạy/resume và các giới hạn:
[CUSTOM_DATASET_ATTACKS.md](report/CUSTOM_DATASET_ATTACKS.md).

Lab chạy **7 container chính**; phần Web đã tách thành frontend, backend và DB:

| Service | Chức năng |
| --- | --- |
| `web-frontend` | Nginx phục vụ giao diện, chuyển API requests tới Backend |
| `backend` | Python API, kết nối tới DB |
| `db` | PostgreSQL, chỉ nhận kết nối DB từ Backend |
| `proxy` | Một Nginx reverse proxy; đổi modern/weak TLS để làm các case |
| `bastion` | SSH jump host, pull image LinuxServer OpenSSH có sẵn |
| `router` | Alpine với NAT, IP forwarding và firewall |
| `zeek` | Một sensor ghi metadata TLS/SSH |

Proxy, Bastion, Router và Zeek vẫn mỗi loại một container. Client nằm trong profile `test`, chỉ được tạo tạm khi thử nghiệm. [TOPOLOGY.md](report/TOPOLOGY.md) mô tả mạng; [README_PLAN.md](report/README_PLAN.md) mô tả các bước hoàn thiện đề tài.

Luồng ứng dụng: **Client → Proxy → Frontend → Backend → DB**. Trong `docker/web/`, code giao diện nằm ở `frontend/`, API ở `backend/`, cấu hình PostgreSQL ở `db/`. Dockerfile có ba build targets; không gom ba dịch vụ trong một container.

Project đã sắp xếp theo cấu trúc đề tài: `data/`, `sensors/`, `src/`, `experiments/`, `tests/`, `docker/`, `report/`. Xem [STRUCTURE.md](report/STRUCTURE.md) để biết vị trí từng phần và các lệnh sau khi chuyển thư mục. `compose.yaml` giữ ở root để tiếp tục dùng `docker compose`.

Zeek metadata-only đã có JSON `conn/ssl/x509/ssh/notice/weird`, rule TLS/SSH, JA3/JA4/HASSH/JA4SSH, SPKI hash và field allowlist. Xem [hướng dẫn Zeek](report/ZEEK_METADATA.md) và [mapping feature](report/ZEEK_FEATURE_MAPPING.md). Kiểm tra bằng `python tests/test_zeek_metadata.py`. `build_sessions.py` chạy privacy validator trước khi xuất CSV; policy result trong CSV là evidence, không tự dùng làm input ML dự đoán cùng nhãn.

Custom lab dataset: `python -m src.data_generation.generator --quick` chạy background + 10 scenario, ghi manifest và xuất labeled CSV có schema/version/checksum, tách session chưa rõ nhãn vào quarantine. Thêm `--parquet` nếu đã cài `experiments/requirements-dataset.txt`. Xem [CUSTOM_DATASET_ATTACKS.md](report/CUSTOM_DATASET_ATTACKS.md); regression test: `python tests/test_custom_dataset.py`. Final validator: `python data/schemas/validate_zeek_metadata.py --dataset <run_directory>`.

Campaign mới: `python scripts/run_dataset_campaign.py` chỉ preview attack v3; thêm `--collect --max-runs 1 --simple-output` để thu một round lúc rảnh với output gọn. Hai file sử dụng là `dataset.csv` (feature + ground-truth label) và `scenario_manifest.csv`; checkpoint/log kiểm tra nằm trong `.internal` của campaign. CSV cập nhật sau mỗi round thành công, không tạo bản sample/split hay manifest riêng từng scenario. Chế độ gọn không dùng `--parquet`. Xem [CUSTOM_DATASET_ATTACKS.md](report/CUSTOM_DATASET_ATTACKS.md). Lịch v1 cũ: [CUSTOM_DATASET_ATTACKS.md](report/CUSTOM_DATASET_ATTACKS.md), cần truyền config v1 rõ ràng khi tạo mới.

Ablation A/B/C đã có bộ tính feature, config và runner offline. Xem mục 8 bên dưới; không cần thêm container. Code đã kiểm thử bằng fixture riêng, chưa đồng nghĩa có kết quả nghiên cứu trên campaign thật.

## 1. Build và chạy

Bật Docker Desktop ở chế độ Linux containers, rồi mở PowerShell:

```powershell
cd D:\NT2205.11.CH-Project
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
docker compose ps
```

Script tạo key bằng một client tạm rồi gỡ client, sau đó build/pull và khởi động 7 services. Bastion pull image trực tiếp, không build Dockerfile riêng. Frontend/Backend/DB và Bastion chỉ nhận public key; private key giữ ở client.

Chạy script start cho lần đầu để public key tồn tại trước khi các SSH servers khởi động. Các lần sau có thể dùng:

```powershell
docker compose up -d --build --wait
```

Kết quả mong đợi: `router`, `web-frontend`, `backend`, `db`, `proxy`, `bastion`, `zeek` đều healthy. Proxy publish HTTPS tại `127.0.0.1:8443` để mở UI trên máy Windows.

### Mở giao diện trên trình duyệt

Mở **https://localhost:8443/**. Certificate tự ký của lab sẽ tạo cảnh báo; chọn **Nâng cao / Advanced → Tiếp tục / Proceed** cho địa chỉ này. Trang hiện cửa hàng **Nook** với 6 sản phẩm đồ công nghệ. Có tìm kiếm, lọc danh mục, giỏ hàng và đặt đơn thử nghiệm.

1. Bấm `+` trên sản phẩm để thêm vào giỏ.
2. Mở **Giỏ hàng**, tăng/giảm số lượng hoặc bỏ sản phẩm. Giỏ được giữ trong trình duyệt khi tải lại trang.
3. Bấm **Đặt hàng thử nghiệm**; trang hiện mã đơn và tổng tiền. Đơn và tồn kho được lưu trong PostgreSQL.

Backend tính giá từ DB, kiểm tra tồn kho và lưu đơn trong một transaction; gửi lại cùng mã yêu cầu không tạo hai đơn. Mỗi sản phẩm tối đa 10 món/đơn. Đây là cửa hàng demo, không có đăng nhập/thanh toán thật và không thu tên, địa chỉ hay thông tin thanh toán.

| API | Chức năng |
| --- | --- |
| `GET /api/products` | Danh mục sản phẩm, giá và tồn kho |
| `POST /api/orders` | Tạo đơn từ `request_id` UUID và `items` gồm `product_id`, `quantity` |
| `GET /api/orders/{id}` | Xem đơn theo mã UUID |
| `GET /api/status` | Kiểm tra backend/DB, trả `db_result: 1` |

Trình duyệt dùng profile `modern`. Nếu vừa test TLS weak, đổi lại bằng:

```powershell
$env:TLS_PROFILE = 'modern'
docker compose up -d --no-deps --wait proxy
```

Luồng trình duyệt Windows đi thẳng vào Proxy qua cổng Docker publish, sau đó Frontend → Backend → DB. Để sinh metadata TLS trên mirror của Router, dùng client lab và `tests/test_lab.ps1`. Dữ liệu sản phẩm/đơn hàng chỉ ở DB nghiệp vụ; không đưa nội dung API vào dataset/LLM. Zeek vẫn chỉ xuất metadata.

## 2. Kiểm tra hoạt động

Test cửa hàng (Proxy phải ở profile modern): `python tests/test_shop.py`. Script kiểm tra dữ liệu đầu vào, giá do server tính, gửi lặp đồng thời, tồn kho và đọc lại đơn đã lưu. Mỗi lần chạy tạo một đơn thử gồm 2 món; chạy riêng, không đồng thời đặt đơn trên UI để bộ đếm tồn kho đối chiếu chính xác.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\test_lab.ps1
python src/features/build_sessions.py
```

Test tạo một client tạm, kiểm tra frontend/backend/DB, modern/weak TLS trên cùng proxy, SSH qua ProxyJump tới cả ba nodes, ACL và Zeek metadata của traffic Frontend→Backend→DB. Cuối test khôi phục profile TLS ban đầu và gỡ client. Test restart Zeek để flush logs nên gây gián đoạn capture ngắn; chỉ dùng khi kiểm tra lab.

CSV xuất ra `data/lab_metadata/sessions.csv`, lấy từ `data/lab_metadata/zeek/conn*.log`, `ssl*.log`, `x509*.log`, `ssh*.log`. CSV là snapshot metadata, chưa có token hóa, attack labels hoặc prediction. Các logs cũ trong `data/lab_metadata/zeek/edge` và `data/lab_metadata/zeek/internal` được giữ làm dữ liệu lịch sử; script mặc định không đọc các thư mục con này.

## 3. Đổi case TLS trên một proxy

Không tạo thêm proxy. Trong PowerShell:

```powershell
$env:TLS_PROFILE = 'weak'
docker compose up -d --no-deps --wait proxy
```

Đổi lại:

```powershell
$env:TLS_PROFILE = 'modern'
docker compose up -d --no-deps --wait proxy
```

Có 6 profiles: `modern`, `weak`, `weak-cert`, `expired-cert`, `wrong-host`, `replaced-cert`, với certificate riêng trong cùng volume; không cần rebuild image để đổi profile. `modern` dùng TLS 1.2/1.3 và ECDHE cho TLS 1.2; `weak` dùng TLS 1.2 RSA/CBC/SHA-1 và RSA certificate 1024-bit. `.env.example` là mẫu nếu muốn lưu lựa chọn vào `.env`. Xem [TLS_PROFILES.md](report/TLS_PROFILES.md) để thử lỗi certificate và chạy `python tests/test_tls_profiles.py`.

## 4. Thử thủ công bằng client tạm

```powershell
docker compose --profile test up -d client
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\trust-lab-hosts.ps1
docker compose exec -T client curl -sk https://172.30.20.10/
docker compose exec -T client curl -sk https://172.30.20.10/api/status
docker compose exec client ssh web-frontend
docker compose exec client ssh backend
docker compose exec client ssh db
```

`/` trả frontend; `/api/status` trả JSON có `db_result: 1` khi Backend gọi PostgreSQL thành công. SSH tới ba nodes tự đi qua Bastion theo SSH config trong client; `ssh web` vẫn là alias của Frontend. Gõ `exit` để thoát SSH. Các lệnh curl ngắn dùng `-k` cho self-signed lab; test tự động kiểm tra certificate/hostname ở profile modern.

Khi profile weak đang chạy, curl dùng:

```powershell
docker compose exec -T client curl -sk --tls-max 1.2 --ciphers 'AES128-SHA:@SECLEVEL=0' https://172.30.20.10/api/status
```

Gỡ client khi xong:

```powershell
docker compose rm -s -f client
```

## 5. Giới hạn của bản lab

Frontend, Backend và DB có IP riêng trong Protected: `172.30.30.10`, `.20`, `.30`. Các port ứng dụng là 8080, 8000, 5432; host ACL chỉ cho phép Frontend→Backend và Backend→DB. DB dùng trust authentication giới hạn Backend IP trong lab. Các bảng `shop_products`, `shop_orders`, `shop_order_items` lưu sản phẩm, đơn và chi tiết đơn. Dữ liệu được seed khi backend khởi động lần đầu; restart không reset đơn/tồn kho. Volume `db-data` được giữ khi tách containers.

Một Zeek nhận VXLAN mirrors từ router và egress của ba nodes để quan sát cả traffic cùng subnet. Monitor interfaces của nodes chỉ gửi bản sao; host ACL chặn application traffic trên Monitor. Router không mirror lại ingress Protected để tránh duplicate replies. Sensor chỉ lưu connection metadata cho HTTP/DB, không nội dung ứng dụng.

Zeek ghi metadata `conn/ssl/x509/ssh/notice/weird`. Không PCAP persistence, TLS decryption hoặc HTTP/SSH content logs trong pipeline. Metadata/CSV nguồn vẫn có IP lab; validator, scenario labeling và rule TLS/SSH đã có. Runner ablation loại IP/ID/nhãn/rule outputs khỏi input ML. Pseudonymization HMAC và agent/response chưa hoàn thiện; kết quả ML cần đánh giá trên dataset thật sau khi thu.

## 6. Khi có lỗi và dừng lab

```powershell
docker compose logs --tail 80 router web-frontend backend db proxy bastion zeek
docker compose down
```

`down` giữ logs và volumes chứa DB/certificates/keys. Khi đổi networks/IP/interface, dùng down/up để tránh attachments cũ. Không cần `down -v` khi chỉ restart lab.

Nếu campaign dừng vì SSH timeout: dữ liệu round hoàn thành vẫn giữ, round failed bị loại. Client đã có `init: true`, SSH fixture có timeout trong container và retry tối đa 3 lần; timeout không tự tính là authentication rejection. Kiểm tra `cleanup_passed` trong run_status rồi dùng `--resume`, không tạo lại campaign từ đầu. Xem [CUSTOM_DATASET_ATTACKS.md](report/CUSTOM_DATASET_ATTACKS.md).
