# app.py
# -*- coding: utf-8 -*-
#
# VibeCode • Assignment A — Single-page UPI demo with JSON-action Assistant
# - One-page, professional grey/white/black UI (mobile-first)
# - UPI deep-link (₹1) + QR, manual UTR confirmation
# - Assistant ALWAYS replies in your JSON contract:
#     {
#       "reply": "<html or text>",
#       "action": "show_payment|ask_transaction|complete|general_chat",
#       "should_send_notification": true/false,
#       "notification_data": {"orderId": "...", "utr": "..."} or null
#     }
# - No register numbers, no Firebase
# - Persists confirmations to ./data/transactions.json
# - Optional Pushover notification (set PUSHOVER_* in .env)
# - Security: CSP (nonce), CSRF token (double-submit), rate limit, no caching
# - Diagnostic endpoint /diag/openai to debug OpenAI connectivity
#
# Quickstart (Windows PowerShell):
#   python -m venv .venv
#   .\.venv\Scripts\Activate
#   pip install flask flask-cors python-dotenv requests itsdangerous
#   # required:
#   # echo OPENAI_API_KEY=sk-... > .env
#   # echo OPENAI_MODEL=gpt-4o-mini >> .env
#   # echo UPI_ID=merchant@bank >> .env
#   # echo MERCHANT_NAME="VibeCode" >> .env
#   # optional (for push):
#   # echo PUSHOVER_USER_KEY=... >> .env
#   # echo PUSHOVER_APP_TOKEN=... >> .env
#   # optional:
#   # echo PORT=8000 >> .env
#   python app.py
#
# Open: http://127.0.0.1:8000

import json
import os
import re
import time
import base64
import secrets
import logging
from datetime import datetime
from typing import Dict, Any, List

import requests
from flask import (
    Flask, request, jsonify, render_template_string, make_response
)
from flask_cors import CORS
from dotenv import load_dotenv
from itsdangerous import URLSafeSerializer

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
load_dotenv()

APP_PORT = int(os.getenv("PORT", "8000"))

OPENAI_API_KEY  = (os.getenv("OPENAI_API_KEY") or "").strip()
OPENAI_MODEL    = (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip()

PUSHOVER_USER_KEY   = (os.getenv("PUSHOVER_USER_KEY") or "").strip()
PUSHOVER_APP_TOKEN  = (os.getenv("PUSHOVER_APP_TOKEN") or "").strip()

UPI_ID        = os.getenv("UPI_ID") or "demo-merchant@bank"
MERCHANT_NAME = os.getenv("MERCHANT_NAME") or "VibeCode"

ASSIGNMENT_AMOUNT_NUM = "1.00"
ASSIGNMENT_AMOUNT_TXT = "₹1.00"
CURRENCY              = "INR"

DATA_DIR  = os.path.join(os.getcwd(), "data")
DATA_FILE = os.path.join(DATA_DIR, "transactions.json")

SECRET_KEY = os.getenv(
    "APP_SECRET",
    base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
)
CSRF_COOKIE = "vc_csrf"
SID_COOKIE  = "vc_sid"
TOKEN_TTL_SECONDS = 60 * 30  # 30 minutes

# ------------------------------------------------------------------------------
# App + Logging
# ------------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("VibeApp")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app, resources={
    r"/chat": {"origins": "*"},
    r"/confirm": {"origins": "*"},
    r"/diag/openai": {"origins": "*"}
})

os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump([], f, ensure_ascii=False, indent=2)

# ------------------------------------------------------------------------------
# Storage & Security helpers
# ------------------------------------------------------------------------------
TXN_REGEX = re.compile(r"^[A-Za-z0-9-]{8,32}$")
S = URLSafeSerializer(SECRET_KEY, salt="csrf")
RATE_BUCKET: Dict[str, List[float]] = {}  # ip -> timestamps
SESSIONS: Dict[str, List[Dict[str, str]]] = {}  # sid -> chat messages (role, content)

def load_transactions() -> list:
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def save_transaction(record: Dict[str, Any]) -> None:
    data = load_transactions()
    data.append(record)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def pushover_notify(title: str, message: str) -> bool:
    if not (PUSHOVER_APP_TOKEN and PUSHOVER_USER_KEY):
        return False
    try:
        r = requests.post(
            "https://api.pushover.net/1/messages.json",
            data={"token": PUSHOVER_APP_TOKEN, "user": PUSHOVER_USER_KEY, "title": title, "message": message},
            timeout=12,
        )
        return r.status_code == 200
    except Exception as e:
        log.error(f"Pushover error: {e}")
        return False

def set_security_headers(resp, script_nonce: str):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{script_nonce}' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    resp.headers["Content-Security-Policy"] = csp
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

def client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

def rate_limit(key: str, limit: int = 20, window: int = 60):
    now = time.time()
    bucket = RATE_BUCKET.setdefault(key, [])
    RATE_BUCKET[key] = [t for t in bucket if now - t < window]
    if len(RATE_BUCKET[key]) >= limit:
        return False
    RATE_BUCKET[key].append(now)
    return True

def issue_csrf() -> str:
    issued_at = int(time.time())
    token = S.dumps({"iat": issued_at})
    return token

def validate_csrf(token: str) -> bool:
    try:
        data = S.loads(token)
        iat = int(data.get("iat", 0))
        if (time.time() - iat) > TOKEN_TTL_SECONDS:
            return False
        return token == request.cookies.get(CSRF_COOKIE, "")
    except Exception:
        return False

def gen_nonce() -> str:
    return base64.b64encode(os.urandom(12)).decode("ascii")

def get_sid() -> str:
    sid = request.cookies.get(SID_COOKIE, "")
    if not sid or len(sid) < 16:
        sid = secrets.token_urlsafe(24)
    return sid

# ------------------------------------------------------------------------------
# JSON-Action Assistant (OpenAI)
# ------------------------------------------------------------------------------
# This prompt mirrors your FPA contract, adapted for Assignment A (no register nos.)
ASSISTANT_SYSTEM_PROMPT = f"""
You are FPA (Freshers Payment Assistant) for a demo checkout. The user can pay {ASSIGNMENT_AMOUNT_TXT} via a UPI deep-link generated on this page.

YOUR POWERS:
- You control the conversation.
- Keep messages short (max 3 short sentences), professional, friendly.
- Use emojis sparingly (👍✨).

CONVERSATION FLOW (adapt as needed):
1. If no payment started: tell them to tap “Pay via UPI” or scan the QR.
2. After they pay: ask them to paste their UTR/Reference and press Confirm.
3. When you receive both orderId and UTR (from user context or messages): acknowledge completion.

RESPONSE FORMAT — ALWAYS return a single JSON object ONLY (no extra text), with this schema:
{{
  "reply": "Your message to the user (plain text or simple HTML like <b>..</b>)",
  "action": "show_payment|ask_transaction|complete|general_chat",
  "should_send_notification": true or false,
  "notification_data": {{"orderId": "...", "utr": "..."}} or null
}}

ACTION GUIDE:
- "show_payment": Nudge them to click Pay via UPI or scan the QR.
- "ask_transaction": Ask them to paste UTR and press Confirm.
- "complete": Payment flow is done (you saw orderId and UTR).
- "general_chat": Small talk or neutral responses.

RULES:
1) NEVER ask for personal data.
2) NEVER claim you did the payment yourself.
3) If user repeats "hi/ok" without context, keep it brief and helpful.
4) If you get the latest orderId (e.g., "ORDER-...") in context but no UTR, use "ask_transaction".
5) If both orderId and UTR are present in context, use "complete" and set should_send_notification=true with notification_data exactly.

You will receive "context" messages from the system that look like:
- CURRENT_ORDER_ID: <id or empty>
- CURRENT_UTR: <utr or empty>
Use them to decide your action.

IMPORTANT: Output MUST be valid JSON only — no leading/trailing prose.
"""

def openai_json_action(sid: str, user_msg: str, current_order_id: str, current_utr: str) -> Dict[str, Any]:
    if not OPENAI_API_KEY:
        # Return safe JSON that matches schema
        return {
            "reply": "Assistant is unavailable (missing API key on server).",
            "action": "general_chat",
            "should_send_notification": False,
            "notification_data": None
        }

    msgs = SESSIONS.setdefault(sid, [])
    # Build conversation with system + recent + fresh user + context note
    history = [{"role": "system", "content": ASSISTANT_SYSTEM_PROMPT}]
    # Compact the memory
    history.extend(msgs[-10:])
    # Inject latest context as a system note (so model can act properly)
    ctx_lines = [
        f"CURRENT_ORDER_ID: {current_order_id or ''}",
        f"CURRENT_UTR: {current_utr or ''}",
        f"AMOUNT: {ASSIGNMENT_AMOUNT_TXT}",
        f"VPA: {UPI_ID}",
        f"PAYEE_NAME: {MERCHANT_NAME}"
    ]
    history.append({"role": "system", "content": "\n".join(ctx_lines)})
    history.append({"role": "user", "content": user_msg})

    try:
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": OPENAI_MODEL,
            "messages": history,
            "temperature": 0.35,
            "max_tokens": 220,
            "response_format": { "type": "json_object" }  # force JSON
        }
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=25)
        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"]
            # Store turn memory (raw assistant JSON string)
            msgs.append({"role": "user", "content": user_msg})
            msgs.append({"role": "assistant", "content": content})
            if len(msgs) > 40:
                SESSIONS[sid] = msgs[-40:]
            try:
                return json.loads(content)  # ensure it's valid JSON
            except Exception:
                log.error("Assistant returned non-JSON despite response_format.")
                return {
                    "reply": "Sorry, I had trouble formatting my response.",
                    "action": "general_chat",
                    "should_send_notification": False,
                    "notification_data": None
                }
        # API error
        log.error(f"OpenAI error: {r.status_code} {r.text}")
        return {
            "reply": "Assistant is temporarily unavailable. Please try again in a moment.",
            "action": "general_chat",
            "should_send_notification": False,
            "notification_data": None
        }
    except Exception as e:
        log.error(f"OpenAI exception: {e}")
        return {
            "reply": "Assistant is temporarily unavailable. Please try again shortly.",
            "action": "general_chat",
            "should_send_notification": False,
            "notification_data": None
        }

# ------------------------------------------------------------------------------
# Diagnostics — OpenAI self test
# ------------------------------------------------------------------------------
def openai_self_test() -> dict:
    try:
        if not OPENAI_API_KEY:
            return {"ok": False, "hint": "OPENAI_API_KEY is empty", "status": 0, "body": None}
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": OPENAI_MODEL or "gpt-4o-mini",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
            "temperature": 0
        }
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=20)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return {"ok": r.status_code == 200, "status": r.status_code, "body": body}
    except Exception as e:
        return {"ok": False, "status": -1, "body": str(e)}

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    nonce = gen_nonce()
    csrf = issue_csrf()
    sid = get_sid()

    html = HTML.replace("__UPI_ID__", UPI_ID)\
               .replace("__MERCHANT_NAME__", MERCHANT_NAME)\
               .replace("__ASSIGNMENT_AMOUNT_NUM__", ASSIGNMENT_AMOUNT_NUM)\
               .replace("__ASSIGNMENT_AMOUNT_TXT__", ASSIGNMENT_AMOUNT_TXT)\
               .replace("__NONCE__", nonce)\
               .replace("__CSRF_TOKEN__", csrf)

    resp = make_response(render_template_string(html))
    resp.set_cookie(CSRF_COOKIE, csrf, max_age=TOKEN_TTL_SECONDS, secure=False, httponly=False, samesite="Lax")
    resp.set_cookie(SID_COOKIE, sid, max_age=60*60*24*7, secure=False, httponly=True, samesite="Lax")
    return set_security_headers(resp, nonce)

@app.route("/confirm", methods=["POST"])
def confirm():
    ip = client_ip()
    if not rate_limit(f"confirm:{ip}", limit=10, window=60):
        return jsonify({"ok": False, "message": "Too many attempts. Please wait a moment."}), 429

    try:
        csrf = request.headers.get("X-CSRF-Token", "")
        if not validate_csrf(csrf):
            return jsonify({"ok": False, "message": "Invalid session token."}), 403

        data = request.get_json() or {}
        order_id = (data.get("orderId") or "").strip()
        utr      = (data.get("utr") or "").strip()
        if not order_id:
            return jsonify({"ok": False, "message": "Order ID missing."}), 400
        if not TXN_REGEX.match(utr):
            return jsonify({"ok": False, "message": "Invalid UTR (8–32 alphanumeric/hyphen)."}), 400

        record = {
            "orderId": order_id,
            "utr": utr[-10:],  # store last 10 for privacy
            "amount": ASSIGNMENT_AMOUNT_TXT,
            "status": "manual_confirmed",
            "ts": datetime.utcnow().isoformat(),
        }
        save_transaction(record)

        # Optional push notification
        pushover_notify("✅ UPI Confirmation", f"Order: {order_id}\nUTR*: ****{record['utr']}\nAmount: {ASSIGNMENT_AMOUNT_TXT}")

        return jsonify({"ok": True, "message": "Thanks! Marked as paid (manual). We’ll verify the UTR."})
    except Exception as e:
        log.error(f"/confirm error: {e}")
        return jsonify({"ok": False, "message": "Server error"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    ip = client_ip()
    if not rate_limit(f"chat:{ip}", limit=30, window=60):
        return jsonify({"reply": "Rate limit reached. Please try again shortly."}), 429
    try:
        csrf = request.headers.get("X-CSRF-Token", "")
        if not validate_csrf(csrf):
            return jsonify({"reply": "Session expired. Refresh the page."}), 403

        data = request.get_json() or {}
        msg  = (data.get("message") or "").strip()
        current_order_id = (data.get("orderId") or "").strip()
        current_utr      = (data.get("utr") or "").strip()
        if not msg:
            return jsonify({"reply": "Please type a message."}), 400

        sid = request.cookies.get(SID_COOKIE, "") or get_sid()
        result = openai_json_action(sid, msg, current_order_id, current_utr)
        # Ensure schema fields exist
        result.setdefault("reply", "")
        result.setdefault("action", "general_chat")
        result.setdefault("should_send_notification", False)
        result.setdefault("notification_data", None)
        return jsonify(result)
    except Exception as e:
        log.error(f"/chat error: {e}")
        return jsonify({
            "reply": "Assistant error. Try again.",
            "action": "general_chat",
            "should_send_notification": False,
            "notification_data": None
        }), 500

@app.route("/diag/openai", methods=["GET"])
def diag_openai():
    res = openai_self_test()
    log.info(f"[DIAG] OpenAI status={res.get('status')} body={res.get('body')}")
    return jsonify(res), (200 if res.get("ok") else 500)

@app.after_request
def harden(resp):
    if "Content-Security-Policy" not in resp.headers:
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Cache-Control"] = "no-store"
    resp.headers["Server"] = "VibeApp"
    return resp

# ------------------------------------------------------------------------------
# HTML (single page; assistant + UPI flow; no admin info shown)
# ------------------------------------------------------------------------------
HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VibeCode • UPI Demo</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<link rel="preconnect" href="https://cdn.jsdelivr.net" />
<script nonce="__NONCE__" defer src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
<style nonce="__NONCE__">
:root{
  --bg:#0b0b0c; --panel:#111213; --muted:#9ca3af; --fg:#e6e7e8;
  --line:#1e1f22; --accent:#a1a1aa; --accent-2:#6b7280;
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#f5f6f7; --panel:#ffffff; --muted:#6b7280; --fg:#0b0b0c;
    --line:#e5e7eb; --accent:#4b5563; --accent-2:#6b7280;
  }
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; background:var(--bg); color:var(--fg);
  font: 15px/1.45 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
}
.container{
  max-width:1100px; margin:0 auto; padding:16px; display:grid; gap:16px;
  grid-template-columns: 1fr; align-items:start;
}
@media(min-width:980px){ .container{ grid-template-columns: 1.1fr .9fr; } }

.card{
  background:var(--panel); border:1px solid var(--line); border-radius:16px;
  box-shadow: 0 8px 28px rgba(0,0,0,.22);
}
.header{
  padding:14px 16px; border-bottom:1px solid var(--line);
  display:flex; align-items:center; gap:10px; justify-content:space-between;
}
.header h2{ margin:0; font-size:1.06rem; font-weight:800; letter-spacing:.2px }
.header .tag{ font-size:.8rem; color:var(--muted); padding:6px 10px; border-radius:999px; border:1px solid var(--line) }
.section{ padding:16px; }
.subtle{ color:var(--muted) }

.kv{ list-style:none; margin:10px 0 14px 0; padding:0 }
.kv li{ display:flex; justify-content:space-between; padding:9px 0; border-bottom:1px dashed var(--line) }
.kv li:last-child{ border-bottom:none }

.row{ display:flex; flex-wrap:wrap; gap:10px; align-items:center }

.btn{
  border:1px solid var(--accent-2); background: linear-gradient(180deg, var(--accent), var(--accent-2));
  color:white; border-radius:12px; padding:12px 14px; font-weight:800; cursor:pointer; user-select:none;
  transition: transform .06s ease, box-shadow .2s ease;
}
.btn:hover{ transform: translateY(-1px); box-shadow:0 10px 18px rgba(0,0,0,.25) }
.btn:active{ transform: translateY(0) }
.btn-ghost{
  background:transparent; border:1px solid var(--line); color:var(--fg);
  padding:11px 13px; border-radius:12px; font-weight:700; cursor:pointer;
}

.badge{ padding:7px 10px; border-radius:999px; border:1px solid var(--line); color:var(--muted); font-size:.82rem }

.input{
  width:100%; background:transparent; border:1px solid var(--line); color:var(--fg);
  border-radius:12px; padding:12px 14px; outline:none;
}
.input:focus{
  border-color: var(--accent); box-shadow:0 0 0 3px color-mix(in oklab, var(--accent) 25%, transparent);
}
.help{ color:var(--muted); font-size:.86rem }

.link{ word-break:break-all; margin-top:8px; border:1px dashed var(--line); padding:10px; border-radius:10px }

.qr{ display:flex; gap:10px; align-items:center; margin-top:10px; flex-wrap:wrap }
.qr canvas{ border-radius:8px; background:white }

.split{
  display:grid; gap:10px; grid-template-columns: 1fr;
}
@media(min-width:520px){ .split{ grid-template-columns: 1fr 1fr; } }

.chat{
  height:540px; overflow:auto; display:flex; flex-direction:column; gap:10px; padding:12px;
  border:1px solid var(--line); border-radius:12px; background: color-mix(in oklab, var(--panel) 92%, black);
}
.msg{
  max-width:86%; padding:11px 13px; border-radius:12px; line-height:1.45; white-space:pre-wrap;
  border:1px solid var(--line);
}
.msg.user{ align-self:flex-end; background: color-mix(in oklab, var(--panel) 85%, white) }
.msg.bot{ align-self:flex-start; background: color-mix(in oklab, var(--panel) 95%, black) }
.time{ font-size:.74rem; color:var(--muted); margin-top:6px; text-align:right }

.composer{
  position: sticky; bottom:0; display:flex; gap:10px; padding-top:10px; background:var(--panel);
}
.composer .input{ flex:1 }

.toast{
  position:fixed; left:50%; transform:translateX(-50%); bottom:14px;
  background:var(--panel); color:var(--fg); border:1px solid var(--line);
  border-radius:10px; padding:10px 12px; display:none; box-shadow:0 8px 24px rgba(0,0,0,.28)
}
.toast.show{ display:block; animation:fade .2s ease }
@keyframes fade { from { opacity:0; transform:translate(-50%, 6px) } to { opacity:1; transform:translate(-50%, 0) } }

footer{ text-align:center; color:var(--muted); padding:12px; margin-top:8px }
</style>
</head>
<body>
  <main class="container" role="main">
    <!-- Left: UPI Flow -->
    <section class="card" aria-labelledby="h-upi">
      <div class="header">
        <h2 id="h-upi">Assignment A • UPI Payment</h2>
        <span class="tag">Amount: __ASSIGNMENT_AMOUNT_TXT__</span>
      </div>
      <div class="section">
        <p class="subtle">Generate a UPI deep-link & QR for __ASSIGNMENT_AMOUNT_TXT__. Confirm manually with your UTR.</p>

        <ul class="kv" role="list" aria-label="Order summary">
          <li><span>Item</span><b>VibeCode Token</b></li>
          <li><span>Quantity</span><b>1</b></li>
          <li><span>Total</span><b>__ASSIGNMENT_AMOUNT_TXT__</b></li>
        </ul>

        <div class="row" style="margin:10px 0 8px">
          <button id="payBtn" class="btn" aria-label="Pay via UPI now">Pay via UPI</button>
          <span id="status" class="badge" aria-live="polite">Awaiting payment</span>
        </div>

        <div id="linkWrap" class="link" style="display:none"></div>

        <div id="qrWrap" class="qr" style="display:none">
          <canvas id="qrCanvas" aria-label="UPI QR"></canvas>
          <div class="help">Scan with any UPI app if the link doesn't auto-open.</div>
        </div>

        <hr style="border:none; border-top:1px solid var(--line); margin:16px 0">

        <h3 class="subtle" style="margin:6px 0">Payment Confirmation</h3>
        <div class="split" style="margin-top:6px">
          <div>
            <label for="orderId" class="help">Order ID</label>
            <input id="orderId" class="input" placeholder="Click Pay via UPI to auto-fill">
          </div>
          <div>
            <label for="utr" class="help">UPI Ref / UTR</label>
            <input id="utr" class="input" placeholder="e.g., 12AB34CD56">
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <button id="confirmBtn" class="btn-ghost" aria-label="Confirm with UTR">Confirm Manually</button>
        </div>
      </div>
    </section>

    <!-- Right: Assistant (JSON-action, OpenAI) -->
    <section class="card" aria-labelledby="h-assistant">
      <div class="header">
        <h2 id="h-assistant">Vibe Assistant</h2>
        <span class="tag">JSON actions</span>
      </div>
      <div class="section">
        <div id="chat" class="chat" aria-live="polite" aria-busy="false">
          <div class="msg bot">👋 Welcome! Tap “Pay via UPI” to generate the link or QR. After paying ₹1, paste your UTR and press Confirm.<div class="time" id="t0"></div></div>
        </div>
        <div class="composer">
          <input id="chatInput" class="input" placeholder="Ask about the flow…" aria-label="Chat message">
          <button id="sendBtn" class="btn" aria-label="Send message">Send</button>
        </div>
      </div>
    </section>
  </main>

  <div id="toast" class="toast" role="status" aria-live="polite">Saved</div>

<script nonce="__NONCE__">
(() => {
  const CSRF = "__CSRF_TOKEN__";
  const PAYEE_VPA="__UPI_ID__";
  const PAYEE_NAME="__MERCHANT_NAME__";
  const AMOUNT="__ASSIGNMENT_AMOUNT_NUM__";
  const CURRENCY="INR";

  const payBtn = document.getElementById("payBtn");
  const statusBadge = document.getElementById("status");
  const linkWrap = document.getElementById("linkWrap");
  const qrWrap = document.getElementById("qrWrap");
  const qrCanvas = document.getElementById("qrCanvas");
  const orderIdInp = document.getElementById("orderId");
  const utrInp = document.getElementById("utr");
  const confirmBtn = document.getElementById("confirmBtn");

  const chatEl = document.getElementById("chat");
  const chatInput = document.getElementById("chatInput");
  const sendBtn = document.getElementById("sendBtn");
  document.getElementById('t0').textContent = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});

  function toast(text){
    const t=document.getElementById("toast");
    t.textContent=text;
    t.classList.add("show");
    setTimeout(()=>t.classList.remove("show"), 1800);
  }

  // ---------- UPI helpers ----------
  function buildOrderId(){
    const ts = new Date().toISOString().replace(/[-:TZ.]/g,"").slice(0,14);
    const rnd = Math.random().toString(36).slice(2,7).toUpperCase();
    return `ORDER-${ts}-${rnd}`;
  }
  function buildUPILink(orderId){
    const p = new URLSearchParams({ pa: PAYEE_VPA, pn: PAYEE_NAME, am: AMOUNT, cu: CURRENCY, tn: orderId, tr: orderId });
    return `upi://pay?${p.toString()}`;
  }
  function openUPI(href){
    const a=document.createElement("a");
    a.href=href; a.rel="noopener"; document.body.appendChild(a); a.click(); a.remove();
  }
  function renderQR(text){
    qrWrap.style.display="flex";
    QRCode.toCanvas(qrCanvas, text, {width:220}, (err)=>{ if(err) console.error(err); });
  }

  payBtn.addEventListener("click", ()=>{
    const orderId=buildOrderId();
    orderIdInp.value=orderId;
    const link=buildUPILink(orderId);
    linkWrap.style.display="block";
    linkWrap.innerHTML=`Deep link generated:<br><a href="${link}">${link}</a>`;
    openUPI(link);
    renderQR(link);
    statusBadge.textContent=`Awaiting payment for ${orderId}`;
    toast("UPI link generated");
  });

  confirmBtn.addEventListener("click", async ()=>{
    const orderId=(orderIdInp.value||"").trim();
    const utr=(utrInp.value||"").trim();
    if(!orderId){ toast("Click Pay via UPI first."); return; }
    if(!/^[A-Za-z0-9-]{8,32}$/.test(utr)){ toast("Enter valid UTR (8–32 chars)."); return; }
    try{
      const r=await fetch("/confirm",{
        method:"POST",
        headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF},
        body:JSON.stringify({orderId,utr})
      });
      const data=await r.json();
      if(data.ok){
        statusBadge.textContent=`Marked paid — ${orderId}, UTR: ${utr.slice(-6)}`;
        utrInp.value="";
        toast("Marked as paid");
      }else{
        toast(data.message||"Could not confirm");
      }
    }catch(e){ toast("Network error"); }
  });

  // ---------- Assistant (JSON action) ----------
  function addMsg(html, me=false){
    const d=document.createElement("div");
    d.className="msg "+(me?"user":"bot");
    d.innerHTML=html+`<div class="time">${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</div>`;
    chatEl.appendChild(d);
    chatEl.scrollTop=chatEl.scrollHeight;
  }

  async function sendActionAware(message){
    const payload={
      message,
      orderId:(orderIdInp.value||"").trim(),
      utr:(utrInp.value||"").trim()
    };
    const res=await fetch("/chat",{
      method:"POST",
      headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF},
      body:JSON.stringify(payload)
    });
    const data=await res.json();
    // data has: reply, action, should_send_notification, notification_data
    addMsg(data.reply || "…");

    switch(data.action){
      case "show_payment":
        // Nudge UI to the pay area
        payBtn.focus();
        break;
      case "ask_transaction":
        utrInp.focus();
        break;
      case "complete":
        if(data.notification_data && data.notification_data.orderId){
          statusBadge.textContent=`Marked paid — ${data.notification_data.orderId}${data.notification_data.utr ? ", UTR: "+String(data.notification_data.utr).slice(-6) : ""}`;
        }
        break;
      default:
        // general_chat: no-op
        break;
    }
  }

  async function sendMsg(){
    const msg=(chatInput.value||"").trim(); if(!msg) return;
    addMsg(msg,true); chatInput.value="";
    try{
      await sendActionAware(msg);
    }catch(_e){
      addMsg("Assistant error. Try again.");
    }
  }
  sendBtn.addEventListener("click", sendMsg);
  chatInput.addEventListener("keypress", e=>{ if(e.key==="Enter") sendMsg(); });
})();
</script>

<footer></footer>
</body>
</html>
"""

# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"🚀 Running at http://127.0.0.1:{APP_PORT}")
    print(f"🔧 Model: {OPENAI_MODEL}")
    print(f"🔐 OPENAI key present: {'yes' if bool(OPENAI_API_KEY) else 'no'}")
    app.run(host="0.0.0.0", port=APP_PORT, debug=False)
