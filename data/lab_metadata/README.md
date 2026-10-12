# Lab metadata

- `zeek/`: log JSON conn/ssl/x509/ssh đang được sensor ghi. Các thư mục `edge`/`internal` bên trong giữ log lịch sử.
- `sessions.csv`: snapshot do `python src/features/build_sessions.py` ghép. Chưa có HMAC host IDs, attack labels hoặc privacy validation hoàn chỉnh.

Không lưu nội dung đơn hàng/API/HTTP/SSH terminal, private keys hay session secrets ở đây. Bảng sản phẩm/đơn hàng thuộc PostgreSQL Docker volume. Metadata sinh tự động được giữ local, không commit.
