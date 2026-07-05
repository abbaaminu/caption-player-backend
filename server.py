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
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
GUMROAD_WEBHOOK_SECRET = os.environ.get("GUMROAD_WEBHOOK_SECRET", "")  # optional extra protection

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
    """Generates a readable unique license key e.g. CLP-XXXX-XXXX-XXXX."""
    raw = uuid.uuid4().hex.upper()
    return f"CLP-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def upsert_license(reference: str, email: str, source: str) -> str:
    """
    Creates (or returns existing) license key for a given payment reference.
    Keyed on `reference` so re-delivered webhooks never create duplicate keys.
    """
    existing = supabase.table("licenses").select("*").eq("reference", reference).execute()
    if existing.data and len(existing.data) > 0:
        print(f"License already exists for reference={reference}, returning existing key.")
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
# LICENSE VERIFICATION — called by the desktop app on startup & activation
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
# PAYSTACK WEBHOOK
# Paystack signs requests with HMAC-SHA512 in the x-paystack-signature header.
# ---------------------------------------------------------------------------
@app.route("/webhook/paystack", methods=["POST"])
def paystack_webhook():
    raw_body = request.get_data()
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
    event = payload.get("event")

    if event == "charge.success":
        data = payload.get("data", {})
        reference = data.get("reference")
        email = (data.get("customer") or {}).get("email", "")
        if reference:
            upsert_license(reference, email, source="paystack")
        else:
            print("Paystack charge.success missing reference — skipped.")

    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# GUMROAD WEBHOOK (replaces Paddle)
# Gumroad sends a simple POST with form-encoded data — no complex HMAC needed.
# Configure the ping URL in: Gumroad product → Edit → Advanced → Ping URL
# Set it to: https://caption-player-backend.onrender.com/webhook/gumroad
#
# Optional extra security: set a GUMROAD_WEBHOOK_SECRET env var and add
# ?secret=YOUR_SECRET to your ping URL in Gumroad. The route checks it below.
# ---------------------------------------------------------------------------
@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    # Optional secret check — add ?secret=YOUR_SECRET to your Gumroad ping URL
    # and set GUMROAD_WEBHOOK_SECRET on Render to the same value.
    if GUMROAD_WEBHOOK_SECRET:
        provided_secret = request.args.get("secret", "")
        if provided_secret != GUMROAD_WEBHOOK_SECRET:
            print("Gumroad webhook secret mismatch — ignoring.")
            return jsonify({"received": False}), 401

    # Gumroad sends form-encoded data (not JSON)
    sale_id    = request.form.get("sale_id", "")
    email      = request.form.get("email", "")
    product    = request.form.get("product_name", "")
    refunded   = request.form.get("refunded", "false").lower()
    disputed   = request.form.get("disputed", "false").lower()
    cancelled  = request.form.get("subscription_cancelled", "false").lower()

    print(f"Gumroad ping | sale_id={sale_id} | email={email} | product={product}")

    if not sale_id:
        print("Gumroad webhook missing sale_id — skipped.")
        return jsonify({"received": True}), 200

    # Handle refunds, disputes, and cancellations — mark license inactive
    if refunded == "true" or disputed == "true" or cancelled == "true":
        try:
            existing = supabase.table("licenses").select("*").eq(
                "reference", sale_id
            ).execute()
            if existing.data and len(existing.data) > 0:
                license_key = existing.data[0]["license_key"]
                supabase.table("licenses").update({"status": "Cancelled"}).eq(
                    "license_key", license_key
                ).execute()
                print(f"License CANCELLED for sale_id={sale_id} key={license_key}")
        except Exception as e:
            print(f"Error cancelling license: {e}")
        return jsonify({"received": True}), 200

    # New successful sale — create the license
    upsert_license(sale_id, email, source="gumroad")
    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# THANK-YOU PAGE — browser lands here after payment from any provider.
# Looks up the license key and deep-links back into the desktop app via
# captionplayer://activate?key=XXXX (no copy-paste needed by the customer).
# ---------------------------------------------------------------------------
@app.route("/thank-you", methods=["GET"])
def thank_you():
    # Paystack appends ?reference= or ?trxref=
    # Gumroad redirects to whatever URL you set as the product's redirect URL
    # — configure it as: https://caption-player-backend.onrender.com/thank-you?reference={sale_id}
    reference = (
        request.args.get("reference")
        or request.args.get("trxref")
        or request.args.get("sale_id")
    )

    if not reference:
        return Response("<h2>Missing payment reference.</h2>", mimetype="text/html"), 400

    license_key = None
    attempts = 0

    # Try up to once — webhook usually arrives before the redirect
    try:
        result = supabase.table("licenses").select("*").eq("reference", reference).execute()
        if result.data and len(result.data) > 0:
            license_key = result.data[0]["license_key"]
    except Exception as e:
        print(f"Lookup error on /thank-you: {e}")

    if license_key:
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Activating Premium Live Caption Player...</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    background: #0f172a; color: #f1f5f9;
                    display: flex; flex-direction: column;
                    align-items: center; justify-content: center;
                    min-height: 100vh; text-align: center; padding: 24px;
                }}
                .card {{
                    background: #1e293b; border: 1px solid #334155;
                    border-radius: 16px; padding: 40px 48px; max-width: 480px;
                }}
                h2 {{ color: #22c55e; margin-bottom: 12px; }}
                .key {{
                    background: #0f172a; border: 1px solid #334155;
                    border-radius: 8px; padding: 12px 20px;
                    font-family: monospace; font-size: 18px;
                    color: #60a5fa; margin: 20px 0; letter-spacing: 2px;
                }}
                .activate-btn {{
                    display: inline-block; background: #3b82f6; color: white;
                    padding: 14px 28px; border-radius: 10px; text-decoration: none;
                    font-weight: 700; font-size: 16px; margin-top: 16px;
                }}
                p {{ color: #94a3b8; line-height: 1.6; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Payment Successful!</h2>
                <p>Your license key:</p>
                <div class="key">{license_key}</div>
                <p>The app is opening automatically to activate your license.<br>
                   If nothing happens, click the button below:</p>
                <a class="activate-btn" href="captionplayer://activate?key={license_key}">
                    Activate Now
                </a>
                <p style="margin-top:20px; font-size:13px;">
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
        </html>
        """
        return Response(html, mimetype="text/html"), 200
    else:
        # Webhook hasn't landed yet — auto-refresh every 2 seconds
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="2;url=/thank-you?reference={reference}">
            <title>Confirming Payment...</title>
            <style>
                body {{
                    font-family: sans-serif; background: #0f172a; color: #f1f5f9;
                    display: flex; align-items: center; justify-content: center;
                    min-height: 100vh; text-align: center;
                }}
                .spinner {{
                    width: 40px; height: 40px; border: 4px solid #334155;
                    border-top-color: #3b82f6; border-radius: 50%;
                    animation: spin 0.8s linear infinite; margin: 0 auto 20px;
                }}
                @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            </style>
        </head>
        <body>
            <div>
                <div class="spinner"></div>
                <h2>Confirming your payment...</h2>
                <p style="color:#94a3b8;">This page refreshes automatically. Usually takes 2-5 seconds.</p>
            </div>
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
