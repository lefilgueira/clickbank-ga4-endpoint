# app.py
import os, json, base64, time, hashlib, logging
from flask import Flask, request, jsonify, make_response
from Crypto.Cipher import AES
import requests

# --- Config básica / logging ---
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("clickbank-ga4")

app = Flask(__name__)
app.url_map.strict_slashes = False  # aceita /rota e /rota/

# --- ENV VARS (configure no Render) ---
GA4_MEASUREMENT_ID = os.getenv("GA4_MEASUREMENT_ID", "G-2XE52R5BN9")
GA4_API_SECRET     = os.getenv("GA4_API_SECRET", "go1jZhJuSia2eno-0t7c5Q")
DEFAULT_CLIENT_ID  = os.getenv("DEFAULT_CLIENT_ID", "555.777")
CLICKBANK_SECRET   = os.getenv("CLICKBANK_SECRET_KEY", "DERCI8871TOBIAS3")

# --- Utils: chave AES e unpad PKCS7 ---
def _aes_key_from_secret(secret: str) -> bytes:
    # conforme INS v8: sha1(secret) -> pega 32 chars hex
    sha1_hex = hashlib.sha1(secret.encode("utf-8")).hexdigest()[:32]
    return sha1_hex.encode("utf-8")

def _pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 16:
        return data
    return data[:-pad]

def decrypt_ins(raw_body: bytes, secret: str) -> dict:
    # body vem como {"notification":"<BASE64>","iv":"<BASE64>"}
    try:
        msg = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid JSON body: {e}")

    try:
        iv_b  = base64.b64decode(msg["iv"])
        enc_b = base64.b64decode(msg["notification"])
    except Exception as e:
        raise ValueError(f"Invalid base64 fields: {e}")

    key_b = _aes_key_from_secret(secret)
    try:
        cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
        decrypted = cipher.decrypt(enc_b)
        decrypted = _pkcs7_unpad(decrypted)
        # tenta UTF-8; se falhar, latin-1
        try:
            txt = decrypted.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            txt = decrypted.decode("latin-1", errors="ignore")
        obj = json.loads(txt)
        return obj
    except Exception as e:
        raise ValueError(f"Decryption/parse error: {e}")

def send_ga4_purchase(order: dict) -> None:
    receipt  = order.get("receipt") or f"TEST-{int(time.time())}"
    value    = float(order.get("totalOrderAmount", 0) or 0)
    currency = order.get("currency", "USD")

    items = []
    for li in order.get("lineItems", [])[:25]:
        title = li.get("productTitle", "Item")
        qty   = int(li.get("quantity", 1) or 1)
        amt   = float(li.get("accountAmount", 0) or 0)
        items.append({"item_name": title, "quantity": qty, "price": amt})

    payload = {
        "client_id": DEFAULT_CLIENT_ID,
        "timestamp_micros": int(time.time() * 1e6),
        "events": [{
            "name": "purchase",
            "params": {
                "transaction_id": receipt,
                "value": value,
                "currency": currency,
                "items": items
            }
        }]
    }
    url = (
        "https://www.google-analytics.com/mp/collect"
        f"?measurement_id={GA4_MEASUREMENT_ID}&api_secret={GA4_API_SECRET}"
    )
    r = requests.post(url, json=payload, timeout=5)
    log.info("GA4 resp %s: %s", r.status_code, r.text[:200])
    r.raise_for_status()

# --- Rotas auxiliares ---
@app.get("/")
def root():
    return "OK", 200

@app.get("/health")
def health():
    return jsonify({"status":"ok","ga4":GA4_MEASUREMENT_ID})

@app.get("/debug")
def debug():
    return jsonify({
        "has_ga4_id": bool(GA4_MEASUREMENT_ID),
        "has_api_secret": bool(GA4_API_SECRET),
        "clickbank_secret_len": len(CLICKBANK_SECRET or ""),
        "default_client_id": DEFAULT_CLIENT_ID,
        "strict_slashes": app.url_map.strict_slashes,
    })

@app.post("/clickbank/ins-echo")
def ins_echo():
    body = request.get_data(as_text=True)
    log.info("INS-ECHO body: %s", body[:500])
    return jsonify({"echo": True, "raw": body}), 200

# --- Rota principal: INS v8 -> GA4 purchase ---
@app.post("/clickbank/ins")
def clickbank_ins():
    try:
        raw = request.get_data()
        order = decrypt_ins(raw, CLICKBANK_SECRET)
        log.info("INS v8 decrypted (trunc): %s", json.dumps(order)[:500])
        send_ga4_purchase(order)
        # 204 = success sem body (ClickBank aceita 200/204)
        return ("", 204)
    except Exception as e:
        log.exception("INS ERROR")
        # 400 p/ diferenciar de erro de infraestrutura (500)
        return make_response({"error": str(e)}, 400)

if __name__ == "__main__":
    # Render expõe a porta via env PORT
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
