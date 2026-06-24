import os
import sys
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from supabase import create_client

# Initialize Flask app
app = Flask(__name__)

# Load local .env file if it exists (for local debugging)
load_dotenv()

# Read credentials directly from environment variables
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")

# Safety validation check
if not supabase_url or not supabase_key:
    print("❌ CRITICAL ERROR: Missing Supabase credentials in Environment Variables!")
    sys.exit(1)

# Initialize Supabase client securely
try:
    supabase = create_client(supabase_url, supabase_key)
    print("🚀 Connected securely to Supabase Database.")
except Exception as e:
    print(f"❌ Failed to initialize Supabase client: {e}")
    sys.exit(1)

@app.route("/verify", methods=["POST"])
def verify_license():
    data = request.get_json() or {}
    license_key = data.get("license_key")
    
    if not license_key:
        return jsonify({"valid": False, "message": "Key parameter missing"}), 400
        
    try:
        # Query your Supabase database 'licenses' table to find the input key
        # Assumes your table columns are named 'license_key' and 'status'
        response = supabase.table("licenses").select("*").eq("license_key", license_key).execute()
        records = response.data
        
        if records and len(records) > 0:
            user_license = records[0]
            status = user_license.get("status", "Active")
            
            if status == "Active":
                print(f"✅ LICENSE VERIFIED: Access granted for key: {license_key}")
                return jsonify({"valid": True, "status": "Active"}), 200
            else:
                print(f"❌ DENIED: License key {license_key} is currently: {status}")
                return jsonify({"valid": False, "message": f"License key is {status}"}), 403
        else:
            print(f"❌ AUTHENTICATION FAILED: Key not found in database: {license_key}")
            return jsonify({"valid": False, "message": "Invalid Activation License Key"}), 403
            
    except Exception as e:
        print(f"⚠️ Database query exception: {e}")
        return jsonify({"valid": False, "message": "Internal Database Error"}), 500

if __name__ == "__main__":
    print("====================================================")
    print("🚀 LIVE CAPTION PLAYER LICENSING INFRASTRUCTURE SERVER")
    print("====================================================")
    
    # Render forces Python apps to use 0.0.0.0 and port 5000 to listen globally
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
