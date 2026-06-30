import os
import sys
import hmac
import hashlib
import time
import uuid

from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from supabase import create_client

app = Flask(__name__)
load_dotenv()

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")

# Secrets for verifying that webhook calls genuinely came from Paystack/Paddle,
# not from anyone who guesses your endpoint URL.
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")  # starts with sk_...
PADDLE_WEBHOOK_SECRET = os.environ.get("PADDLE_WEBHOOK_SECRET")  # from Paddle dashboard

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
    """Generates a readable, unique license key, e.g. CLP-XXXX-XXXX-XXXX."""
    raw = uuid.uuid4().hex.upper()
    return f"CLP-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def upsert_license(reference: str, email: str, source: str) -> str:
    """
    Creates (or returns existing) license key for a given payment reference.
    Keyed on `reference` so re-delivered webhooks don't create duplicate keys.
    """
    existing = supabase.table("licenses").select("*").eq("reference", reference).execute()
    if existing.data and len(existing.data) > 0:
        return existing.data[0]["license_key"]

    license_key = generate_license_key()
    supabase.table("licenses").insert({
        "license_key": license_key,
        "status": "Active",
        "email": email,
        "reference": reference,
        "source": source,
    }).execute()
    print(f"License created for reference={reference} source={source}: {license_key}")
    return license_key


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "message": "Caption Player Licensing Server is running smoothly!"
    })


@app.route("/verify", methods=["POST"])
def verify_license():
    data = request.get_json() or {}
    license_key = data.get("license_key")

    if not license_key:
        return jsonify({"valid": False, "message": "Key parameter missing"}), 200

    try:
        response = supabase.table("licenses").select("*").eq("license_key", license_key.strip()).execute()
        records = response.data

        if records and len(records) > 0:
            user_license = records[0]
            status = user_license.get("status", "Active")

            if status == "Active":
                print(f"LICENSE VERIFIED: Access granted for key: {license_key}")
                return jsonify({"valid": True, "status": "Active"}), 200
            else:
                print(f"DENIED: License key {license_key} is currently: {status}")
                return jsonify({"valid": False, "message": f"License key is {status}"}), 200
        else:
            print(f"AUTHENTICATION FAILED: Key not found in database: {license_key}")
            return jsonify({"valid": False, "message": "Invalid Activation License Key"}), 200

    except Exception as e:
        print(f"Database query exception: {e}")
        return jsonify({"valid": False, "message": "Internal Database Connection Timeout"}), 200


# ---------------------------------------------------------------------------
# PAYSTACK WEBHOOK
# ---------------------------------------------------------------------------
@app.route("/webhook/paystack", methods=["POST"])
def paystack_webhook():
    raw_body = request.get_data()  # MUST use raw bytes for signature check, not parsed JSON
    signature = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        print("PAYSTACK_SECRET_KEY not set - rejecting webhook for safety.")
        return jsonify({"received": False}), 500

    computed_hash = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed_hash, signature):
        print("Paystack webhook signature mismatch - ignoring request.")
        return jsonify({"received": False}), 401

    payload = request.get_json() or {}
    event = payload.get("event")

    if event == "charge.success":
        data = payload.get("data", {})
        reference = data.get("reference")
        email = (data.get("customer") or {}).get("email", "")

        if reference:
            upsert_license(reference, email, source="paystack")
        else:
            print("Paystack charge.success event missing reference; skipped.")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# PADDLE WEBHOOK (Paddle Billing — HMAC signature in 'Paddle-Signature' header)
# ---------------------------------------------------------------------------
def verify_paddle_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Paddle Billing sends header like: 'ts=1700000000;h1=abcdef...'
    The signed string is '{ts}:{raw_body}', HMAC-SHA256 with your webhook secret.
    """
    if not PADDLE_WEBHOOK_SECRET or not signature_header:
        return False

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


@app.route("/webhook/paddle", methods=["POST"])
def paddle_webhook():
    raw_body = request.get_data()
    signature_header = request.headers.get("Paddle-Signature", "")

    if not verify_paddle_signature(raw_body, signature_header):
        print("Paddle webhook signature mismatch - ignoring request.")
        return jsonify({"received": False}), 401

    payload = request.get_json() or {}
    event_type = payload.get("event_type")

    if event_type == "transaction.completed":
        tx_data = payload.get("data", {})
        reference = tx_data.get("id")  # Paddle transaction id, used as our reference
        email = (tx_data.get("customer") or {}).get("email", "")

        if reference:
            upsert_license(reference, email, source="paddle")
        else:
            print("Paddle transaction.completed event missing id; skipped.")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# THANK-YOU / DEEP-LINK HANDOFF PAGE
# Paystack and Paddle should redirect the browser HERE after checkout.
# This page looks up the license (webhooks usually beat the redirect, but we
# poll briefly in case the webhook hasn't landed yet) and then bounces the
# browser into the desktop app via captionplayer://activate?key=XXXX
# ---------------------------------------------------------------------------
@app.route("/thank-you", methods=["GET"])
def thank_you():
    # Paystack appends ?reference=... or ?trxref=... ; Paddle can be configured
    # to append ?transaction_id={checkout.id} in its success_url settings.
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
        html = f"""
        <html>
        <head><meta charset="utf-8"><title>Activating...</title></head>
        <body style="font-family: sans-serif; text-align:center; padding-top:60px;">
            <h2>Payment successful!</h2>
            <p>Your license key: <b>{license_key}</b></p>
            <p>Opening Premium Live Caption Player to activate automatically...</p>
            <p>If nothing happens, click below:</p>
            <a href="captionplayer://activate?key={license_key}">Activate Now</a>
            <script>
                window.location.href = "captionplayer://activate?key={license_key}";
            </script>
        </body>
        </html>
        """
        return Response(html, mimetype="text/html"), 200
    else:
        # Webhook may not have landed yet — auto-refresh this page for a few seconds.
        html = """
        <html>
        <head><meta charset="utf-8"><meta http-equiv="refresh" content="2"><title>Processing...</title></head>
        <body style="font-family: sans-serif; text-align:center; padding-top:60px;">
            <h2>Confirming your payment...</h2>
            <p>This page will refresh automatically. This usually takes a few seconds.</p>
        </body>
        </html>
        """
        return Response(html, mimetype="text/html"), 200


if __name__ == "__main__":
    print("====================================================")
    print("LIVE CAPTION PLAYER LICENSING INFRASTRUCTURE SERVER")
    print("====================================================")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
