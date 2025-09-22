#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import os, json, base64, re, logging, requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

app = Flask(__name__)
app.url_map.strict_slashes = False  # aceita /rota e /rota/

# ------------ CONFIG ------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

GA4_MEASUREMENT_ID = os.getenv("GA4_MEASUREMENT_ID", "")
GA4_API_SECRET = os.getenv("GA4_API_SECRET", "")
CLICKBANK_SECRET_KEY = os.getenv("CLICKBANK_SECRET_KEY", "")
DEFAULT_CLIENT_ID = os.getenv("DEFAULT_CLIENT_ID", "555.777")
FORCE_HTTPS_VERIFY = os.getenv("FORCE_HTTPS_VERIFY", "true").lower() != "false"

GA4_ENDPOINT = (
    f"https://www.google-analytics.com/mp/collect?measurement_id={GA4_MEASUREMENT_ID}&api_secret={GA4_API_SECRET}"
    if GA4_MEASUREMENT_ID and GA4_API_SECRET else None
)

# ------------ HELPERS ------------
def _derive_aes_key(secret: str) -> bytes:
    """Garante tamanho 16/24/32 bytes (AES) por padding/trunc."""
    key_bytes = (secret or "").encode("utf-8")
    if len(key_bytes) in (16, 24, 32): return key_bytes
    if len(key_bytes) < 16: return key_bytes.ljust(16, b"\0")
    if len(key_bytes) <= 24: return key_bytes[:24].ljust(24, b"\0")
    return key_bytes[:32].ljust(32, b"\0")

def decrypt_ins_v8(notification_b64: str, iv_b64: str, secret_key: str) -> dict:
    if not secret_key:
        raise ValueError("CLICKBANK_SECRET_KEY is not set")
    try:
        iv = base64.b64decode(iv_b64)
        data = base64.b64decode(notification_b64)
    except Exception as e:
        raise ValueError(f"base64_decode_failed: {e}") from e
    key = _derive_aes_key(secret_key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(data), AES.block_size)
    except Exception as e:
        raise ValueError(f"aes_decrypt_failed: {e}") from e
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"json_parse_failed: {e}") from e

def extract_purchase_params(ins: dict) -> dict:
    tx_type = (ins.get("transactionType") or "").upper()
    if tx_type not in ("SALE", "TEST_SALE", "BILL", "TEST_BILL"):
        raise ValueError(f"Skipping non-sale transactionType: {tx_type}")
    receipt = ins.get("receipt") or ins.get("attempt", {}).get("receipt")

    # amount
    amount = None
    for k in ("totalProductAmount", "totalAccountAmount", "orderTotal"):
        v = ins.get(k) or ins.get("transactionItem", {}).get(k)
        if v is not None:
            try:
                amount = float(v); break
            except Exception:
                pass
    if amount is None: amount = 0.0

    currency = ins.get("currency") or ins.get("attempt", {}).get("currency") or "USD"

    # client_id a partir de trackingCodes (cid:12345.67890 ou _ga=...)
    client_id = DEFAULT_CLIENT_ID
    tracking_codes = ins.get("trackingCodes") or ins.get("attempt", {}).get("trackingCodes") or []
    if isinstance(tracking_codes, list):
        for code in tracking_codes:
            if isinstance(code, str):
                if code.startswith("cid:"):
                    client_id = code[4:].strip(); break
                if code.startswith("_ga="):
                    parts = code.split(".")
                    if len(parts) >= 4:
                        client_id = f"{parts[-2]}.{parts[-1]}"; break

    params = {
        "transaction_id": str(receipt) if receipt else f"CB-{int(datetime.utcnow().timestamp())}",
        "value": round(amount, 2),
        "currency": currency,
    }

    # items (opcional)
    items = []
    for li in ins.get("lineItems") or []:
        name = li.get("productTitle") or li.get("itemNo") or "Item"
        price = li.get("itemAmount") or li.get("price") or amount
        try: price = float(price)
        except Exception: price = amount
        qty = 1
        try: qty = int(li.get("quantity", 1))
        except Exception: pass
        items.append({"item_name": str(name)[:100], "price": round(price, 2), "quantity": qty})
    if items:
        params["items"] = items

    return {"client_id": client_id, "params": params}

def post_to_ga4(client_id: str, params: dict):
    if not GA4_ENDPOINT:
        raise ValueError("GA4 endpoint not configured (missing GA4_MEASUREMENT_ID or GA4_API_SECRET).")
    payload = {"client_id": client_id, "events": [{"name": "purchase", "params": params}]}
    verify = FORCE_HTTPS_VERIFY
    return requests.post(GA4_ENDPOINT, json=payload, timeout=10, verify=verify)

def _looks_b64(s: str) -> bool:
    if not s: return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s))

# ------------ ROUTES ------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok", "service": "clickbank-ins-ga4"}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ga4": GA4_MEASUREMENT_ID}), 200

@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({
        "has_ga4_id": bool(GA4_MEASUREMENT_ID),
        "has_api_secret": bool(GA4_API_SECRET),
        "clickbank_secret_len": len(CLICKBANK_SECRET_KEY or ""),
        "strict_slashes": False
    }), 200

@app.route("/clickbank/ins-echo", methods=["GET","POST"])
def clickbank_ins_echo():
    body_json = request.get_json(silent=True) or {}
    form_fields = {k: v for k, v in request.form.items()}
    nb = body_json.get("notification")
    ib = body_json.get("iv")
    nf = form_fields.get("notification")
    ivf = form_fields.get("iv")
    return jsonify({
        "ok": True, "method": request.method,
        "has_json": bool(body_json), "has_form": bool(form_fields),
        "json": {
            "notification_len": len(nb) if nb else 0,
            "iv_len": len(ib) if ib else 0,
            "notification_looks_b64": _looks_b64(nb),
            "iv_looks_b64": _looks_b64(ib),
        },
        "form": {
            "notification_len": len(nf) if nf else 0,
            "iv_len": len(ivf) if ivf else 0,
            "notification_looks_b64": _looks_b64(nf),
            "iv_looks_b64": _looks_b64(ivf),
        }
    }), 200

@app.route("/clickbank/ins", methods=["GET", "POST"])
def clickbank_ins():
    if request.method == "GET":
        return jsonify({"status": "ready"}), 200
    try:
        # Stage 1: inputs
        body_json = request.get_json(silent=True) or {}
        notification_b64 = body_json.get("notification") or request.form.get("notification")
        iv_b64 = body_json.get("iv") or request.form.get("iv")
        if not notification_b64 or not iv_b64:
            return jsonify({"error": "Missing 'notification' or 'iv' (json or form).", "stage": "validate-input"}), 400

        # Stage 2: decrypt
        try:
            ins = decrypt_ins_v8(notification_b64, iv_b64, CLICKBANK_SECRET_KEY)
        except Exception as e:
            return jsonify({"error": f"decrypt_failed: {str(e)}", "stage": "decrypt"}), 500

        # Stage 3: map
        try:
            mapped = extract_purchase_params(ins)
        except Exception as e:
            return jsonify({"error": f"map_failed: {str(e)}", "stage": "map"}), 500

        # Stage 4: post to GA4
        try:
            resp = post_to_ga4(mapped["client_id"], mapped["params"])
        except Exception as e:
            return jsonify({"error": f"ga4_post_failed: {str(e)}", "stage": "ga4"}), 502

        if not (200 <= resp.status_code < 300):
            return jsonify({"status": "ins_ok", "ga4_status": resp.status_code, "ga4_error": resp.text, "stage": "ga4"}), 502

        return jsonify({"status": "ok", "ga4_status": resp.status_code}), 200

    except Exception as e:
        return jsonify({"error": f"unexpected: {str(e)}", "stage": "catch-all"}), 500

if __name__ == "__main__":
    # Render costuma expor porta 10000
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
