# app_ins.py (ou dentro do seu app.py)
import os, json, base64, time, hashlib, requests
from flask import Flask, request, jsonify, make_response
from Crypto.Cipher import AES

app = Flask(__name__)

GA4_MEASUREMENT_ID = os.getenv("GA4_MEASUREMENT_ID", "G-2XE52R5BN9")
GA4_API_SECRET     = os.getenv("GA4_API_SECRET", "go1jZhJuSia2eno-0t7c5Q")
DEFAULT_CLIENT_ID  = os.getenv("DEFAULT_CLIENT_ID", "555.777")  # seu client_id está ok
CLICKBANK_SECRET   = os.getenv("CLICKBANK_SECRET_KEY", "DERCI8871TOBIAS3")  # 16 chars

def _aes_key_from_secret(secret: str) -> bytes:
    # Conforme o exemplo oficial (v8): SHA1(secret) e usar os 32 primeiros chars hex
    sha1_hex = hashlib.sha1(secret.encode("utf-8")).hexdigest()[:32]
    return sha1_hex.encode("utf-8")

def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data  # fallback seguro
    return data[:-pad_len]

def decrypt_ins(raw_body: bytes, secret: str) -> dict:
    msg = json.loads(raw_body.decode("utf-8"))
    iv_b  = base64.b64decode(msg["iv"])
    enc_b = base64.b64decode(msg["notification"])
    key_b = _aes_key_from_secret(secret)
    cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
    decrypted = cipher.decrypt(enc_b)
    # alguns exemplos removem chars de controle; PKCS7 resolve na maioria dos casos
    try:
        decrypted = _pkcs7_unpad(decrypted)
        txt = decrypted.decode("utf-8", errors="ignore")
        return json.loads(txt)
    except Exception:
        # tentativa alternativa (alguns exemplos usam ISO-8859-1)
        try:
            txt = decrypted.decode("latin-1", errors="ignore").strip()
            return json.loads(txt)
        except Exception as e:
            raise ValueError(f"Decryption/JSON parse failed: {e}")

def send_ga4_purchase(order: dict) -> None:
    # Campos principais conforme exemplo do INS v8
    receipt = order.get("receipt") or f"TEST-{int(time.time())}"
    value   = float(order.get("totalOrderAmount", 0) or 0)
    currency = order.get("currency", "USD")

    # Itens (opcional mas bom para qualidade de dados)
    items = []
    for li in order.get("lineItems", []):
        title = li.get("productTitle", "Item")
        qty = int(li.get("quantity", 1) or 1)
        amt = float(li.get("accountAmount", 0) or 0)
        items.append({
            "item_name": title,
            "quantity": qty,
            "price": amt
        })

    payload = {
        "client_id": DEFAULT_CLIENT_ID,  # estável; se você tiver client_id real, pode usar
        "timestamp_micros": int(time.time() * 1e6),
        "events": [{
            "name": "purchase",
            "params": {
                "transaction_id": receipt,
                "value": value,
                "currency": currency,
                "items": items[:25],  # limite razoável
            }
        }]
    }
    url = f"https://www.google-analytics.com/mp/collect?measurement_id={GA4_MEASUREMENT_ID}&api_secret={GA4_API_SECRET}"
    r = requests.post(url, json=payload, timeout=4)
    # Se quiser, logue r.status_code e r.text para troubleshooting
    r.raise_for_status()

@app.route("/clickbank/ins", methods=["POST"])
def clickbank_ins():
    try:
        raw = request.get_data()  # RAW JSON do INS
        order = decrypt_ins(raw, CLICKBANK_SECRET)
        # opcional: log de teste
        # print("INS v8 decrypted:", json.dumps(order)[:400])
        send_ga4_purchase(order)
        # ClickBank considera 200-204 em até 3s como sucesso
        return ("", 204)
    except Exception as e:
        # loga a exceção para aparecer no Render
        print("INS ERROR:", repr(e))
        # devolve 400/401 para diferenciar de 500 genérico
        return make_response({"error": str(e)}, 400)

# endpoints de saúde (você já tem /health e /debug)





