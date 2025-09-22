# ClickBank INS v8 -> GA4 (Flask, debug-ready)

## Variáveis de ambiente
- GA4_MEASUREMENT_ID = G-2XE52R5BN9
- GA4_API_SECRET     = go1jZhJuSia2eno-0t7c5Q
- CLICKBANK_SECRET_KEY = DERCI8871TOBIAS3
- DEFAULT_CLIENT_ID  = 555.777

## Render
- Build:  pip install -r requirements.txt
- Start:  python app.py

## Rotas
- GET  /                    -> {"status":"ok","service":"clickbank-ins-ga4"}
- GET  /health              -> {"status":"ok","ga4":"G-..."}
- GET  /debug               -> {"has_ga4_id":true,...,"clickbank_secret_len":16}
- GET|POST /clickbank/ins-echo -> 200 com info de comprimentos e se parece base64
- GET|POST /clickbank/ins   -> handler real; retorna {"stage": "..."} em erros

## Testes rápidos
curl -s https://SEU.onrender.com/health
curl -i -X POST "https://SEU.onrender.com/clickbank/ins" -H "Content-Type: application/x-www-form-urlencoded" --data "notification=BAD&iv=BAD"
