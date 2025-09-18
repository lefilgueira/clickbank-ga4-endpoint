# ClickBank INS v8 -> GA4 Endpoint (Flask)

This service receives ClickBank Instant Notifications (INS v8), decrypts them with your ClickBank Secret Key, and forwards a GA4 `purchase` event via Measurement Protocol.

## 1) Configure environment variables
- `GA4_MEASUREMENT_ID` (e.g., `G-XXXXXXXX`)
- `GA4_API_SECRET` (GA4 > Data Stream > Measurement Protocol API secrets)
- `CLICKBANK_SECRET_KEY` (same key set in ClickBank Advanced Tools; 16 chars recommended)
- `DEFAULT_CLIENT_ID` (optional fallback, like `12345.67890`)
- `FORCE_HTTPS_VERIFY` (optional; set to `false` only for testing)

## 2) Install & run locally
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export GA4_MEASUREMENT_ID=G-XXXXXXX
export GA4_API_SECRET=YOUR_API_SECRET
export CLICKBANK_SECRET_KEY=YOUR_INS_SECRET
python app.py
```

## 3) Expose the endpoint
Deploy or use ngrok, then set the public URL in ClickBank Advanced Tools:
`Vendor Settings > My Site > Advanced Tools > Instant Notification URL`
Endpoint: POST `https://<your-host>/clickbank/ins`

## 4) Passing client_id via tracking
Add a tracking code like `cid:12345.67890` in your HopLink (TID). We'll read it back from INS to attribute in GA4.
