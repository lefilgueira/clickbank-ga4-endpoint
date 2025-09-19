# ClickBank INS v8 -> GA4 (Flask, debug-ready)

Routes:
- GET /                   -> service ok
- GET /health             -> shows GA4 ID
- GET /debug              -> booleans + clickbank_secret_len (should be 16)
- GET|POST /clickbank/ins-echo -> always 200, echoes received fields
- GET|POST /clickbank/ins -> real INS with staged error JSON

Render:
- Build:  pip install -r requirements.txt
- Start:  python app.py
- ENV: GA4_MEASUREMENT_ID, GA4_API_SECRET, CLICKBANK_SECRET_KEY (16 chars), DEFAULT_CLIENT_ID (optional)
