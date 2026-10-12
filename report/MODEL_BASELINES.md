# Baseline Random Forest, XGBoost và LightGBM

## 1. Chỉnh tham số ở đâu?

Mở `src/models/baselines.py`. Code tạo model, tiền xử lý, train và tham số
được gom trong file này. `src/models/ablation.py` chứa hàm dùng chung và
runner A/B/C gọi lại cùng `train_models()` của baseline. Các file trong `scripts` chỉ là lệnh chạy.
Tham số được đặt ngay đầu source:

- `DATASET_DIRECTORY`, `OUTPUT_DIRECTORY`: đường dẫn dữ liệu và kết quả.
- `SEEDS = [42]`: chỉ một seed cố định.
- `CV_SPLITS = 3`: cross-validation theo thời gian, nhóm theo run.
- `MODEL_PARAMETERS`: bộ tham số cố định của ba model.
- `A_NUMERIC`, `A_CATEGORICAL`, `B_NUMERIC`, `B_CATEGORICAL`: danh sách feature.
- `LOG_COLUMNS`: các cột không âm dùng log1p.
- `MIN_CATEGORY_FREQUENCY = 5`: gom các giá trị chữ hiếm theo train.

Đã bỏ JSON cấu hình baseline và CLI `--config`. Schema/checksum của dataset
vẫn cần để đọc đúng dữ liệu. JSON feature của runner A/B/C khác được giữ vì
chế độ `--config` tương thích lệnh cũ còn dùng; mặc định cả hai runner lấy feature và tham số từ source.

## 2. Lệnh chạy

```powershell
.\.venv\Scripts\python.exe -m pip install -r experiments/requirements-baselines.txt
# Chỉ kiểm tra, không tạo thư mục kết quả:
.\.venv\Scripts\python.exe scripts/run_model_baselines.py
# Train ba model trên Fused:
.\.venv\Scripts\python.exe scripts/run_model_baselines.py --train
# Hoặc train trên từng nhóm A/B/C:
.\.venv\Scripts\python.exe scripts/run_model_baselines.py --groups A B C --train
```

Không cần bật Docker để train. Nếu thiếu subset, chạy hai lệnh chuẩn bị:

```powershell
.\.venv\Scripts\python.exe scripts/audit_custom_dataset.py
.\.venv\Scripts\python.exe scripts/prepare_custom_ablation.py
```

## 3. Dữ liệu đầu vào

Subset thật tại `experiments/datasets/custom_data_v1_ablation/`: 30.000 session,
27.000 benign và toàn bộ 3.000 mẫu bất thường. Giữ bốn nhãn riêng: benign,
misconfiguration, policy_violation, attack_behavior.

| Split | Số mẫu | Block thu |
|---|---:|---|
| Train | 18.000 | 1–3 |
| Validation | 6.000 | 4 |
| Test | 6.000 | 5 |

Đây là block thu theo giờ thực, không khẳng định là năm ngày lịch.
Dùng lại reader/validator trong `src/models/ablation.py` và
`src/features/ablation_training.py`: checksum/privacy, nhãn, session/run không trùng
giữa split và split đúng thứ tự thời gian. Không random lại split.

A=L3/L4, B=TLS/SSH, C=A+B. Allowlist chặn nhãn, ID, scenario, role, host token
và rule output đi vào input. Vector packet được chuyển thành thống kê session.

## 4. Tiền xử lý trong source

`numeric_array()` đọc trường số. Missing/non-finite thành NaN; chuỗi số sai
hoặc số âm ở cột vốn không âm gây lỗi. Validator chạy trước vẫn có thể chặn record
không hợp lệ; bước xử lý số không bỏ qua validator.

`log1p(x)` áp dụng cho bytes/packets/duration/rate/IAT và một số count.
Ví dụ bytes 0/100/1.000.000 thành khoảng 0/4,62/13,82. Không cắt outlier vì
traffic cực lớn có thể là tín hiệu attack. Không log port, cipher code hoặc số ngày
certificate còn hiệu lực; số âm của cert đã hết hạn được giữ.
Log là biến đổi đơn điệu, không bảo đảm tăng điểm cho model cây.

`categorical_array()` bỏ khoảng trắng hai đầu; trường trống có nhóm missing.
Không lower-case toàn bộ fingerprint/banner.

`prepare_features()` thực hiện:

1. Tính trung vị từng cột từ train sau log; dùng nó điền số thiếu của cả ba split.
2. Cột train trống hoàn toàn dùng 0; thêm missing indicator cho mọi cột số để
   phân biệt số 0 thật với số được điền. Không sửa CSV gốc.
3. Fit one-hot encoder bằng train; gom giá trị chữ xuất hiện dưới 5 lần thành nhóm
   hiếm. Giá trị mới ở validation/test dùng nhóm hiếm nếu có, nếu không dùng toàn zero.
4. Ghép số + missing indicators + categorical thành ma trận dense float32 chung
   cho ba model. Dense giữ số 0 thật cho XGBoost, nhưng có thể dùng nhiều RAM khi
   số categorical tăng mạnh.

Không fit preprocessing bằng validation/test. Không cần scaler cho model cây.
Không dùng SMOTE hoặc nhân bản attack. Sample weight balanced tính từ nhãn train
và dùng giống nhau cho cả ba model.

## 5. Huấn luyện

`make_model()` tạo model. `train_models()` fit train, kiểm tra validation và đánh giá test.
Tham số cố định; không còn vòng tuning/chọn cấu hình:

| Model | Tham số chính |
|---|---|
| Random Forest | 100 cây, depth 12, min_samples_leaf 2 |
| XGBoost | 100 cây, depth 6, learning_rate 0.1, hist |
| LightGBM | 100 cây, 31 lá, learning_rate 0.1 |

Cross-validation chỉ dùng tập train 18.000 mẫu. Các run được xếp theo timestamp
thật rồi chia ba fold: train là các run quá khứ, validation là nhóm run tiếp theo.
Không chia session của cùng run sang hai phía, không shuffle hoặc dùng random K-fold.
Preprocessing và sample weight được fit lại bằng train của từng fold.
Fold train phải có đủ bốn nhãn để cả ba model học được cùng bài toán; nếu thiếu,
code báo lỗi, không âm thầm bỏ fold. Fold validation có thể thiếu nhãn, macro-F1
vẫn tính theo đủ bốn nhãn và lớp không có mẫu được zero_division=0.

CV hiển thị từng fold và điểm trung bình trên console. Tham số vẫn cố định, không
tuning bằng CV. Sau đó fit lại trên toàn bộ train 18.000, kiểm tra validation 6.000
và đánh giá final test 6.000 riêng. Final test không tham gia CV.
`summary.csv` chứa chín metric của final test; thời gian là fit/predict cuối,
không cộng thời gian CV. Suffix `_mean` được giữ để tương thích, nhưng chỉ một seed
nên giá trị là kết quả của seed 42.

Fused: 3 model × (3 fold + 1 final fit) = 12 lần fit. A/B/C: 36 lần fit.
Validation/test chỉ predict. Không refit train+validation hoặc dùng early stopping.
Khi đổi tham số/preprocessing, ghi rõ protocol trong báo cáo để phân biệt lượt cũ.

## 6. Output chỉ một file

```text
experiments/results/model_baselines/ketqua_lan1/
└── summary.csv
```

Lần sau là ketqua_lan2, ketqua_lan3… không ghi đè kết quả cũ.
Audit không tạo thư mục. Lỗi trước khi có kết quả thì dọn thư mục rỗng vừa tạo.
Không lưu JSON, predictions, matrix feature hoặc model inference.

| Cột | Ý nghĩa |
|---|---|
| accuracy_mean | Tỷ lệ dự đoán đúng nhãn trên final test |
| recall_macro_mean | Recall trung bình đều bốn lớp trên final test |
| tpr_attack_mean | TP/(TP+FN), positive là attack_behavior |
| fpr_attack_mean | FP/(FP+TN), negative gồm benign/misconfiguration/policy_violation |
| train_seconds_mean | Thời gian final model.fit trên toàn train, đơn vị giây |
| predict_seconds_mean | Thời gian model.predict trên toàn final test, đơn vị giây |
| macro_f1_mean | Macro-F1 final test |
| mcc_mean | MCC đa lớp, từ -1 đến 1; càng gần 1 càng tốt |
| ap_attack_mean | Average Precision từ xác suất attack_behavior; càng gần 1 càng tốt |

Recall/F1 dùng macro vì bốn lớp không cân bằng. TPR ở đây là recall riêng của
attack_behavior, nên khác recall macro. Xuất chín metric, trung bình
với seed 42; thêm hai cột feature_group/model để nhận biết từng dòng.
FPR attack không phải benign false-alarm rate: denominator gồm cả misconfiguration
và policy_violation. Nếu muốn positive là mọi bất thường thì phải định nghĩa lại,
không tự gộp các nhãn trong baseline này.

Thời gian baseline chỉ đo fit/predict của model; không gồm đọc dữ liệu, preprocessing,
validation, chuyển nhãn hoặc ghi CSV. Không phải thời gian trên mỗi session.
Runner A/B/C dùng cùng hàm train và cùng phạm vi đo thời gian. Tính xác suất
cho AP nằm ngoài timer predict. MCC đánh giá cả bốn lớp; AP chỉ đánh giá
attack_behavior so với ba lớp còn lại. AP không phải diện tích PR tính theo hình thang.

0,95 tương ứng 95%. Điểm trước đây RF 95,59%, XGBoost 95,08%, LightGBM 95,14%
là protocol cũ có tuning và preprocessing khác; không coi là điểm của code mới.
Kết quả lab chưa chứng minh hiệu quả trên public dataset hoặc mạng thực tế.
