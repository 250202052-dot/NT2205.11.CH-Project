"""Integration test against the running demo. Leaves one labeled test order in DB."""
import concurrent.futures
import json
import ssl
import urllib.error
import urllib.request
import uuid

BASE = "https://localhost:8443"
CONTEXT = ssl._create_unverified_context()  # Self-signed localhost lab certificate.


def request(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers={"Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(req, context=CONTEXT, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.code, json.load(response)


def catalog():
    status, result = request("/api/products")
    assert status == 200 and result["currency"] == "VND"
    return {p["id"]: p for p in result["products"]}


def main():
    products = catalog()
    assert len(products) >= 6
    selected = next(p for p in products.values() if p["stock"] >= 2)
    product_id = selected["id"]
    before = selected["stock"]
    for items in ([], [{"product_id": product_id, "quantity": 0}],
                  [{"product_id": product_id, "quantity": -1}],
                  [{"product_id": product_id, "quantity": True}],
                  [{"product_id": product_id, "quantity": 11}],
                  [{"product_id": 999999, "quantity": 1}],
                  [{"product_id": product_id, "quantity": 1}] * 2):
        status, _ = request("/api/orders", {"request_id": str(uuid.uuid4()), "items": items})
        assert status == 400, (items, status)
    assert catalog()[product_id]["stock"] == before
    order_id = str(uuid.uuid4())
    body = {"request_id": order_id, "items": [{"product_id": product_id, "quantity": 2, "price": 1}], "total": 1}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request("/api/orders", body), range(2)))
    assert sorted(status for status, _ in results) == [200, 201]
    for _, order in results:
        assert order["id"] == order_id and order["total"] == selected["price"] * 2
    assert catalog()[product_id]["stock"] == before - 2, "Retries must not subtract stock twice"
    status, saved = request("/api/orders/" + order_id)
    assert status == 200 and saved["items"][0]["quantity"] == 2
    body["items"][0]["quantity"] = 1
    assert request("/api/orders", body)[0] == 409
    assert request("/api/missing")[0] == 404
    assert request("/api/orders/" + str(uuid.uuid4()))[0] == 404
    print("PASS: catalog, validation, server prices, concurrent retry, stock and saved order.")
    print("Test order: " + order_id)


if __name__ == "__main__":
    main()
