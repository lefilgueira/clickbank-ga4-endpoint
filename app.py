#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import os
import json
import base64
import logging
import requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

"""
ClickBank INS v8 -> GA4 Measurement Protocol bridge

Environment variables required:
  - GA4_MEASUREMENT_ID  (e.g., G-XXXXXXXXXX)
  - GA4_API_SECRET      (from GA4 Data Stream > Measurement Protocol API secrets)
  - CLICKBANK_SECRET_KEY (same key you set in ClickBank Advanced Tools; 16 chars recommended)

Optional:
  - DEFAULT_CLIENT_ID (fallback if you cannot pass client_id from site to ClickBank; format "12345.67890")
  - FORCE_HTTPS_VERIFY=false (to disable SSL verification in dev only)
"""

app = Flask(__name__)

# Basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

GA4_MEASUREMENT_ID = os.getenv("GA4_MEASUREMENT_ID", "G-XXXXXXX")
GA4_API_SECRET = os.getenv("GA4_API_SECRET", "YOUR_API_SECRET")
CLICKBANK_SECRET_KEY = os.getenv("CLICKBANK_SECRET_KEY", "")
DEFAULT_CLIENT_ID = os.getenv("DEFAULT_CLIENT_ID", "555.777")
FORCE_HTTPS_VERIFY = os.getenv("FORCE_HTTPS_VERIFY", "true").lower() != "false"

GA4_ENDPOINT = f"https://www.google-analytics.com/mp/collect?measurement_id={GA4_MEASUREMENT_ID}&api_secret={GA4_API_SECRET}"

def _derive_aes_key(secret: str) -> bytes:
    """Ensure AES key is 16/24/32 bytes by padding/truncating deterministically."""
    key_bytes = secret.encode("utf-8")
    if len(key_bytes) in (16, 24, 32):
        return key_bytes
    if len(key_bytes) < 16:
        return key_bytes.ljust(16, b"\0")
    if len(key_bytes) <= 24:
        return key_bytes[:24].ljust(24, b"\0")
    return key_bytes[:32].ljust(32, b"\0")

def decrypt_ins_v8(notification_b64: str, iv_b64: str, secret_key: str) -> dict:
    """Decrypt ClickBank INS v8 payload (AES/CBC) -> dict"""
    if not secret_key:
        raise ValueError("CLICKBANK_SECRET_KEY is not set")
    key = _derive_aes_key(secret_key)
    iv = base64.b64decode(iv_b64)
    data = base64.b64decode(notification_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data), AES.block_size)
    return json.loads(plaintext.decode("utf-8"))

def extract_purchase_params(ins: dict) -> dict:
    """Map ClickBank fields -> GA4 purchase params."""
    tx_type = ins.get("transactionType", "").upper()
    if tx_type not in ("SALE", "TEST_SALE", "BILL", "TEST_BILL"):
        raise ValueError(f"Skipping non-sale transactionType: {tx_type}")

    receipt = ins.get("receipt") or ins.get("attempt", {}).get("receipt")
    amount = None
    for k in ("totalProductAmount", "totalAccountAmount", "orderTotal"):
        v = ins.get(k) or ins.get("transactionItem", {}).get(k)
        if v is not None:
            try:
                amount = float(v)
                break
            except Exception:
                pass
    if amount is None:
        amount = 0.0

    currency = ins.get("currency") or ins.get("attempt", {}).get("currency") or "USD"

    client_id = os.getenv("DEFAULT_CLIENT_ID", "555.777")
    tracking_codes = ins.get("trackingCodes") or ins.get("attempt", {}).get("trackingCodes") or []
    if isinstance(tracking_codes, list):
        for code in tracking_codes:
            if isinstance(code, str):
                if code.startswith("cid:"):
                    client_id = code[4:].strip()
                    break
                if code.startswith("_ga="):
                    parts = code.split(".")
                    if len(parts) >= 4:
                        client_id = f"{parts[-2]}.{parts[-1]}"
                        break

    params = {
        "transaction_id": str(receipt) if receipt else f"CB-{int(datetime.utcnow().timestamp())}",
        "value": round(amount, 2),
        "currency": currency,
    }

    items = []
    line_items = ins.get("lineItems") or []
    if isinstance(line_items, list):
        for li in line_items:
            name = li.get("productTitle") or li.get("itemNo") or "Item"
            price = li.get("itemAmount") or li.get("price") or amount
            try:
                price = float(price)
            except Exception:
                price = amount
            items.append({
                "item_name": str(name)[:100],
                "price": round(price, 2),
                "quantity": int(li.get("quantity", 1)),
            })
    if items:
        params["items"] = items

    return {"client_id": client_id, "params": params}

def post_to_ga4(client_id: str, params: dict) -> requests.Response:
    payload = {
        "client_id": client_id,
        "events": [{"name": "purchase", "params": params}]
    }
    verify = FORCE_HTTPS_VERIFY
    resp = requests.post(GA4_ENDPOINT, json=payload, timeout=10, verify=verify)
    return resp

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ga4": GA4_MEASUREMENT_ID}), 200

@app.route("/clickbank/ins", methods=["POST"])
def clickbank_ins():
    try:
        body = request.get_json(force=True, silent=False)
        if not body:
            return jsonify({"error": "Empty body"}), 400

        notification_b64 = body.get("notification")
        iv_b64 = body.get("iv")
        if not notification_b64 or not iv_b64:
            return jsonify({"error": "Missing 'notification' or 'iv' fields"}), 400

        ins = decrypt_ins_v8(notification_b64, iv_b64, CLICKBANK_SECRET_KEY)

        mapped = extract_purchase_params(ins)
        resp = post_to_ga4(mapped["client_id"], mapped["params"])

        if not (200 <= resp.status_code < 300):
            return jsonify({"status": "ins_ok", "ga4_status": resp.status_code, "ga4_error": resp.text}), 502

        return jsonify({"status": "ok", "ga4_status": resp.status_code}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
