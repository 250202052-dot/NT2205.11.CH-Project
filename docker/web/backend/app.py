"""Shop fixture. Application content stays in PostgreSQL, outside telemetry."""
import hashlib
import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import psycopg2
from psycopg2.extras import RealDictCursor

PRODUCTS = [
    (1, "Bàn phím cơ Orbit", "Bàn phím", "Gõ êm, kết nối không dây và một góc bàn thật gọn.", 1290000, 120, "keyboard", "sage", "Bán chạy"),
    (2, "Tai nghe Airwave", "Âm thanh", "Âm thanh cân bằng, đệm tai mềm cho cả ngày tập trung.", 1890000, 80, "headphones", "sand", "Được yêu thích"),
    (3, "Chuột không dây Pebble", "Phụ kiện", "Nhẹ, vừa tay, chuyển đổi dễ dàng giữa hai thiết bị.", 590000, 150, "mouse", "lavender", ""),
    (4, "Loa mini Echo", "Âm thanh", "Một chút nhạc cho bàn làm việc. Nhỏ gọn, pin bền.", 990000, 100, "speaker", "peach", "Mới"),
    (5, "Đèn bàn Halo", "Góc làm việc", "Ánh sáng dịu, điều chỉnh độ sáng theo nhịp làm việc.", 790000, 90, "lamp", "sage", ""),
    (6, "Hub USB-C Link", "Phụ kiện", "Thêm kết nối cho laptop trong một thiết kế tối giản.", 690000, 110, "hub", "sand", ""),
]

def connect():
    return psycopg2.connect(host=os.environ.get("DB_HOST", "172.30.30.30"), dbname="postgres", user="postgres", connect_timeout=3)

def initialize():
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS shop_products (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
                    description TEXT NOT NULL, price INTEGER NOT NULL CHECK (price > 0),
                    stock INTEGER NOT NULL CHECK (stock >= 0), illustration TEXT NOT NULL,
                    color TEXT NOT NULL, badge TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS shop_orders (
                    id UUID PRIMARY KEY, request_hash TEXT NOT NULL,
                    total BIGINT NOT NULL CHECK (total > 0),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS shop_order_items (
                    order_id UUID REFERENCES shop_orders(id),
                    product_id INTEGER REFERENCES shop_products(id),
                    name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK (quantity > 0),
                    unit_price INTEGER NOT NULL CHECK (unit_price > 0),
                    PRIMARY KEY (order_id, product_id)
                );
            """)
            cursor.executemany("INSERT INTO shop_products VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING", PRODUCTS)

def order_details(cursor, order_id):
    cursor.execute("SELECT id::text, total, created_at FROM shop_orders WHERE id=%s", (order_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    order = dict(row)
    order["created_at"] = order["created_at"].isoformat()
    order["status"] = "confirmed"
    cursor.execute("SELECT product_id, name, quantity, unit_price FROM shop_order_items WHERE order_id=%s ORDER BY product_id", (order_id,))
    order["items"] = [dict(item) for item in cursor.fetchall()]
    return order

class RequestError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message

class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, result):
        body = json.dumps(result, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path in ("/health", "/api/status"):
                with connect() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT 1")
                        result = cursor.fetchone()[0]
                self.send_json(200, {"service": "web-backend", "status": "ok", "db_result": result})
            elif path == "/api/products":
                with connect() as connection:
                    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                        cursor.execute("SELECT * FROM shop_products ORDER BY id")
                        products = [dict(row) for row in cursor.fetchall()]
                self.send_json(200, {"products": products, "currency": "VND"})
            elif path.startswith("/api/orders/"):
                try:
                    order_id = str(uuid.UUID(path.removeprefix("/api/orders/")))
                except ValueError:
                    raise RequestError(400, "Mã đơn hàng không hợp lệ.")
                with connect() as connection:
                    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                        order = order_details(cursor, order_id)
                if order is None:
                    raise RequestError(404, "Không tìm thấy đơn hàng.")
                self.send_json(200, order)
            else:
                raise RequestError(404, "Đường dẫn không tồn tại.")
        except RequestError as error:
            self.send_json(error.status, {"error": error.message})
        except psycopg2.Error:
            self.send_json(503, {"error": "DB tạm thời không khả dụng. Vui lòng thử lại.", "status": "db_unavailable"})

    def do_POST(self):
        try:
            if urlsplit(self.path).path != "/api/orders":
                raise RequestError(404, "Đường dẫn không tồn tại.")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 16384:
                    raise RequestError(400, "Nội dung đơn hàng không hợp lệ.")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError()
                order_id = str(uuid.UUID(body.get("request_id", "")))
                items = body.get("items")
                if not isinstance(items, list) or not 1 <= len(items) <= 20:
                    raise ValueError()
                quantities = {}
                for item in items:
                    if not isinstance(item, dict):
                        raise ValueError()
                    product_id, quantity = item.get("product_id"), item.get("quantity")
                    if type(product_id) is not int or type(quantity) is not int or not 1 <= quantity <= 10:
                        raise ValueError()
                    if product_id in quantities:
                        raise ValueError()
                    quantities[product_id] = quantity
            except (ValueError, TypeError, AttributeError, UnicodeDecodeError):
                raise RequestError(400, "Giỏ hàng không hợp lệ; mỗi sản phẩm cần số lượng từ 1 đến 10.")
            request_hash = hashlib.sha256(json.dumps(sorted(quantities.items())).encode()).hexdigest()
            with connect() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Serialize retries with the same request key; commit stock and order together.
                    cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (order_id,))
                    cursor.execute("SELECT request_hash FROM shop_orders WHERE id=%s", (order_id,))
                    previous = cursor.fetchone()
                    if previous:
                        if previous["request_hash"] != request_hash:
                            raise RequestError(409, "Mã yêu cầu đã được dùng cho giỏ hàng khác.")
                        order = order_details(cursor, order_id)
                        status = 200
                    else:
                        cursor.execute("SELECT * FROM shop_products WHERE id=ANY(%s) ORDER BY id FOR UPDATE", (sorted(quantities),))
                        products = cursor.fetchall()
                        if len(products) != len(quantities):
                            raise RequestError(400, "Sản phẩm không tồn tại.")
                        for product in products:
                            if product["stock"] < quantities[product["id"]]:
                                raise RequestError(409, f'{product["name"]} không đủ hàng. Vui lòng giảm số lượng.')
                        total = sum(p["price"] * quantities[p["id"]] for p in products)
                        cursor.execute("INSERT INTO shop_orders (id,request_hash,total) VALUES (%s,%s,%s)", (order_id, request_hash, total))
                        for product in products:
                            quantity = quantities[product["id"]]
                            cursor.execute("INSERT INTO shop_order_items VALUES (%s,%s,%s,%s,%s)", (order_id, product["id"], product["name"], quantity, product["price"]))
                            cursor.execute("UPDATE shop_products SET stock=stock-%s WHERE id=%s", (quantity, product["id"]))
                        order = order_details(cursor, order_id)
                        status = 201
            self.send_json(status, order)
        except RequestError as error:
            self.send_json(error.status, {"error": error.message})
        except psycopg2.Error:
            self.send_json(503, {"error": "Chưa xác nhận được đơn hàng. Vui lòng thử lại."})

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    initialize()
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
