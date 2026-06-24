import os
import secrets
from flask import Flask, request, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv() # Load system parameters safely from a hidden root file

app = Flask(__name__)

# Initialize your connection parameters to your cloud cluster database
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")

# --- ENDPOINT 1: APP VALIDATION INTAKE ---
@app.route("/verify-key", methods=["POST"])
def verify_license_key():
    """Validates the input string provided by the desktop application."""
    data = request.json or {}
    user_key = data.get("license_key")

    if not user_key:
        return jsonify({"status": "error", "message": "Missing key parameter."}), 400

    # Query your Supabase database to find matching record data configurations
    query = supabase.table("subscriptions").select("*").eq("license_key", user_key).execute()
    records = query.data

    if not records:
        return jsonify({"status": "invalid", "message": "License key not found."}), 404

    subscription = records[0]
    
    # Returns 'active' or 'expired' depending on customer billing history
    return jsonify({
        "status": subscription.get("status"),
        "customer_email": subscription.get("email")
    }), 200


# --- ENDPOINT 2: PAYSTACK WEBHOOK EVENT LISTENER ---
@app.route("/paystack-webhook", methods=["POST"])
def paystack_webhook_receiver():
    """Listens for automated transaction events directly from Paystack servers."""
    
    # Security check: verify that the incoming request actually came from Paystack
    paystack_signature = request.headers.get("X-Paystack-Signature")
    if not paystack_signature:
        return jsonify({"status": "denied", "message": "Missing signature verification profile."}), 401
        
    payload = request.json or {}
    event = payload.get("event")
    event_data = payload.get("data", {})
    
    # Filter the exact billing event you care about
    if event == "subscription.create" or event == "charge.success":
        customer_email = event_data.get("customer", {}).get("email")
        
        # Generate a cryptographically secure 16-character license key string
        generated_license = f"LIVE-CAP-{secrets.token_hex(8).upper()}"
        
        # Insert the subscription details into your database
        try:
            supabase.table("subscriptions").insert({
                "email": customer_email,
                "license_key": generated_license,
                "status": "active"
            }).execute()
            
            # TODO: Add your mail server code here (e.g., SendGrid, Mailgun) 
            # to email the 'generated_license' key to the 'customer_email' address.
            print(f"Success! Created license {generated_license} for client {customer_email}")
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # Paystack expects a standard 200 HTTP response to acknowledge receipt of the webhook
    return jsonify({"status": "processed"}), 200

if __name__ == "__main__":
    print("====================================================")
    print("🚀 LIVE CAPTION PLAYER LICENSING INFRASTRUCTURE SERVER")
    print("====================================================")
    
    # Force host to 0.0.0.0 so Render can broadcast your server live to the internet
    app.run(host="0.0.0.0", port=5000, debug=False)
