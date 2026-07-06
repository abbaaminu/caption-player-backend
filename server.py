import os
import sys
import hmac
import hashlib
import uuid

from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from supabase import create_client

app = Flask(__name__)
load_dotenv()

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
PAYSTACK_SECRET_KEY   = os.environ.get("PAYSTACK_SECRET_KEY")
PADDLE_WEBHOOK_SECRET = os.environ.get("PADDLE_WEBHOOK_SECRET")

if not supabase_url or not supabase_key:
    print("CRITICAL ERROR: Missing Supabase credentials in Environment Variables!")
    sys.exit(1)

try:
    supabase = create_client(supabase_url, supabase_key)
    print("Connected securely to Supabase Database.")
except Exception as e:
    print(f"Failed to initialize Supabase client: {e}")
    sys.exit(1)


def generate_license_key() -> str:
    raw = uuid.uuid4().hex.upper()
    return f"CLP-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def upsert_license(reference: str, email: str, source: str) -> str:
    """Creates or returns existing license for a payment reference (idempotent)."""
    existing = supabase.table("licenses").select("*").eq("reference", reference).execute()
    if existing.data and len(existing.data) > 0:
        print(f"License already exists for reference={reference}")
        return existing.data[0]["license_key"]

    license_key = generate_license_key()
    supabase.table("licenses").insert({
        "license_key": license_key,
        "status": "Active",
        "email": email,
        "reference": reference,
        "source": source,
    }).execute()
    print(f"License created | source={source} | ref={reference} | key={license_key}")
    return license_key


# ---------------------------------------------------------------------------
# ROOT — health check
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "message": "Caption Player Licensing Server is running smoothly!"
    })


# ---------------------------------------------------------------------------
# LICENSE VERIFICATION — called by the desktop app
# ---------------------------------------------------------------------------
@app.route("/verify", methods=["POST"])
def verify_license():
    data = request.get_json() or {}
    license_key = data.get("license_key")

    if not license_key:
        return jsonify({"valid": False, "message": "Key parameter missing"}), 200

    try:
        response = supabase.table("licenses").select("*").eq(
            "license_key", license_key.strip()
        ).execute()
        records = response.data

        if records and len(records) > 0:
            status = records[0].get("status", "Active")
            if status == "Active":
                print(f"LICENSE VERIFIED: {license_key}")
                return jsonify({"valid": True, "status": "Active"}), 200
            else:
                print(f"LICENSE DENIED ({status}): {license_key}")
                return jsonify({"valid": False, "message": f"License is {status}"}), 200
        else:
            print(f"LICENSE NOT FOUND: {license_key}")
            return jsonify({"valid": False, "message": "Invalid Activation License Key"}), 200

    except Exception as e:
        print(f"Database error in /verify: {e}")
        return jsonify({"valid": False, "message": "Server error, please try again"}), 200


# ---------------------------------------------------------------------------
# PAYSTACK WEBHOOK — HMAC-SHA512 signature in x-paystack-signature header
# ---------------------------------------------------------------------------
@app.route("/webhook/paystack", methods=["POST"])
def paystack_webhook():
    raw_body  = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        print("PAYSTACK_SECRET_KEY not set — rejecting for safety.")
        return jsonify({"received": False}), 500

    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        print("Paystack signature mismatch — ignoring.")
        return jsonify({"received": False}), 401

    payload = request.get_json() or {}
    if payload.get("event") == "charge.success":
        data      = payload.get("data", {})
        reference = data.get("reference")
        email     = (data.get("customer") or {}).get("email", "")
        if reference:
            upsert_license(reference, email, source="paystack")
        else:
            print("Paystack charge.success missing reference — skipped.")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# PADDLE WEBHOOK — Paddle Billing HMAC-SHA256
# Header format: 'ts=1700000000;h1=abcdef...'
# Signed payload: '{ts}:{raw_body}'
# ---------------------------------------------------------------------------
def verify_paddle_signature(raw_body: bytes, signature_header: str) -> bool:
    if not PADDLE_WEBHOOK_SECRET or not signature_header:
        return False
    try:
        parts = dict(p.split("=", 1) for p in signature_header.split(";") if "=" in p)
        ts = parts.get("ts")
        h1 = parts.get("h1")
        if not ts or not h1:
            return False
        signed_payload = f"{ts}:".encode("utf-8") + raw_body
        computed = hmac.new(
            PADDLE_WEBHOOK_SECRET.encode("utf-8"),
            signed_payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, h1)
    except Exception as e:
        print(f"Paddle signature verification error: {e}")
        return False


@app.route("/webhook/paddle", methods=["POST"])
def paddle_webhook():
    raw_body         = request.get_data()
    signature_header = request.headers.get("Paddle-Signature", "")

    if not verify_paddle_signature(raw_body, signature_header):
        print("Paddle webhook signature mismatch — ignoring.")
        return jsonify({"received": False}), 401

    payload    = request.get_json() or {}
    event_type = payload.get("event_type", "")
    print(f"Paddle event received: {event_type}")

    if event_type == "transaction.completed":
        tx_data   = payload.get("data", {})
        reference = tx_data.get("id", "")
        email     = (tx_data.get("customer") or {}).get("email", "")
        if reference:
            upsert_license(reference, email, source="paddle")
        else:
            print("Paddle transaction.completed missing id — skipped.")

    elif event_type in ("subscription.canceled", "subscription.paused"):
        # Mark license inactive when customer cancels or payment fails
        sub_data  = payload.get("data", {})
        reference = sub_data.get("transaction_id", "") or sub_data.get("id", "")
        if reference:
            try:
                existing = supabase.table("licenses").select("*").eq("reference", reference).execute()
                if existing.data and len(existing.data) > 0:
                    license_key = existing.data[0]["license_key"]
                    supabase.table("licenses").update({"status": "Cancelled"}).eq(
                        "license_key", license_key
                    ).execute()
                    print(f"License CANCELLED for ref={reference} key={license_key}")
            except Exception as e:
                print(f"Error cancelling license: {e}")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# PADDLE CHECKOUT PAGE
# Desktop app opens this URL in the browser. It loads Paddle.js and opens the
# checkout overlay immediately. Approved domain: premiumcaptionapp.vercel.app
# so we serve this from the Vercel site (paddle-checkout.html), NOT from here.
# This route is kept as a fallback only.
# ---------------------------------------------------------------------------
@app.route("/paddle-checkout", methods=["GET"])
def paddle_checkout_fallback():
    return Response(
        "<script>window.location.href='https://premiumcaptionapp.vercel.app/paddle-checkout.html';</script>",
        mimetype="text/html"
    ), 302


# ---------------------------------------------------------------------------
# THANK-YOU PAGE — browser lands here after payment from any provider.
# Looks up license key and deep-links back into the desktop app.
# ---------------------------------------------------------------------------
@app.route("/thank-you", methods=["GET"])
def thank_you():
    reference = (
        request.args.get("reference")
        or request.args.get("trxref")
        or request.args.get("transaction_id")
    )

    if not reference:
        return Response("<h2>Missing payment reference.</h2>", mimetype="text/html"), 400

    license_key = None
    try:
        result = supabase.table("licenses").select("*").eq("reference", reference).execute()
        if result.data and len(result.data) > 0:
            license_key = result.data[0]["license_key"]
    except Exception as e:
        print(f"Lookup error on /thank-you: {e}")

    if license_key:
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Activating Premium Live Caption Player...</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background:#0f172a; color:#f1f5f9;
      display:flex; flex-direction:column;
      align-items:center; justify-content:center;
      min-height:100vh; text-align:center; padding:24px;
    }}
    .card {{
      background:#1e293b; border:1px solid #334155;
      border-radius:16px; padding:40px 48px; max-width:480px; width:100%;
    }}
    h2 {{ color:#22c55e; margin-bottom:12px; font-size:24px; }}
    .key {{
      background:#0f172a; border:1px solid #334155;
      border-radius:8px; padding:12px 20px;
      font-family:monospace; font-size:18px;
      color:#60a5fa; margin:20px 0; letter-spacing:2px;
    }}
    .btn {{
      display:inline-block; background:#3b82f6; color:white;
      padding:14px 28px; border-radius:10px; text-decoration:none;
      font-weight:700; font-size:16px; margin-top:16px;
    }}
    p {{ color:#94a3b8; line-height:1.6; margin-top:8px; font-size:14px; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Payment Successful!</h2>
    <p>Your license key:</p>
    <div class="key">{license_key}</div>
    <p>The app is opening automatically to activate your license.<br>
       If nothing happens, click the button below:</p>
    <a class="btn" href="captionplayer://activate?key={license_key}">Activate Now</a>
    <p style="margin-top:20px; font-size:12px; color:#475569;">
      Keep this key safe — you can also paste it manually into<br>
      the "Paste your Activation License Key here" box in the app.
    </p>
  </div>
  <script>
    setTimeout(function() {{
      window.location.href = "captionplayer://activate?key={license_key}";
    }}, 800);
  </script>
</body>
</html>"""
        return Response(html, mimetype="text/html"), 200

    else:
        # Webhook hasn't landed yet — auto-refresh every 2 seconds
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="2;url=/thank-you?reference={reference}">
  <title>Confirming Payment...</title>
  <style>
    body {{
      font-family:sans-serif; background:#0f172a; color:#f1f5f9;
      display:flex; align-items:center; justify-content:center;
      min-height:100vh; text-align:center;
    }}
    .spinner {{
      width:40px; height:40px; border:4px solid #334155;
      border-top-color:#3b82f6; border-radius:50%;
      animation:spin 0.8s linear infinite; margin:0 auto 20px;
    }}
    @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
    p {{ color:#94a3b8; margin-top:8px; }}
  </style>
</head>
<body>
  <div>
    <div class="spinner"></div>
    <h2>Confirming your payment...</h2>
    <p>This page refreshes automatically. Usually takes 2-5 seconds.</p>
  </div>
</body>
</html>"""
        return Response(html, mimetype="text/html"), 200


if __name__ == "__main__":
    print("====================================================")
    print("LIVE CAPTION PLAYER LICENSING INFRASTRUCTURE SERVER")
    print("====================================================")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
