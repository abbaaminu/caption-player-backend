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

# Secrets for verifying webhook validity
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")  
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
    raw_body = request.get_data()  
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
# PADDLE WEBHOOK (Paddle Billing)
# ---------------------------------------------------------------------------
def verify_paddle_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Validates Paddle's HMAC-SHA256 timestamped payload.
    """
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
    except Exception:
        return False


@app.route("/webhook/paddle", methods=["POST"])
def paddle_webhook():
    raw_body = request.get_data()
    signature_header = request.headers.get("Paddle-Signature", "")

    if not verify_paddle_signature(raw_body, signature_header):
        print("Paddle webhook signature mismatch - ignoring request.")
        return jsonify({"received": False}), 401

    payload = request.get_json() or {}
    event_type = payload.get("event_type")

    # Catch subscription.created or explicit transaction completion states
    if event_type in ["subscription.created", "transaction.completed"]:
        tx_data = payload.get("data", {})
        reference = tx_data.get("id")  
        
        customer_obj = tx_data.get("customer", {})
        email = customer_obj.get("email", "") if isinstance(customer_obj, dict) else ""

        if reference:
            upsert_license(reference, email, source="paddle")
        else:
            print(f"Paddle event {event_type} missing reference ID; skipped.")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# THANK-YOU / DEEP-LINK HANDOFF PAGE
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
    # Poll up to 3 times to give asynchronous live webhooks time to write to Supabase
    for _ in range(3):
        try:
            result = supabase.table("licenses").select("*").eq("reference", reference).execute()
            if result.data and len(result.data) > 0:
                license_key = result.data[0]["license_key"]
                break
        except Exception as e:
            print(f"Lookup error on /thank-you: {e}")
        time.sleep(1)

    if license_key:
        html = f"""
        <html>
        <head>
            <meta charset="utf-8">
            <title>Activating Player...</title>
            <script>
                window.onload = function() {{
                    window.location.href = "captionplayer://activate?key={license_key}";
                    setTimeout(function() {{
                        document.getElementById('status').innerText = "If your player didn't open automatically, please copy your key manually:";
                    }}, 2500);
                }};
            </script>
        </head>
        <body style="font-family: sans-serif; text-align:center; padding-top:60px; background-color: #f8f9fa; color: #333;">
            <div style="max-width:500px; margin:0 auto; padding:20px; border:1px solid #ddd; background:#fff; border-radius:8px;">
                <h2 style="color: #28a745;">Payment Successful!</h2>
                <p id="status">Launching Premium Live Caption Player...</p>
                <div style="background:#f1f1f1; padding:15px; border-radius:4px; font-family:monospace; font-weight:bold; font-size:1.2em; margin: 15px 0; border: 1px dashed #bbb; letter-spacing: 1px;">
                    {license_key}
                </div>
            </div>
        </body>
        </html>
        """
        return Response(html, mimetype="text/html")
    else:
        return Response("<h2>Payment received! We are still processing your license key. Please refresh this page in 5 seconds.</h2>", mimetype="text/html")

if __name__ == "__main__":
    # Production configurations should be set via gunicorn on Render
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
