import os
import re
import math
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# --- 1. MONGODB CONNECTION ---
# Render pulls the 'MONGO_URI' from your environment variables automatically
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.ids_database
logs_collection = db.attack_logs

# --- 2. IDS DETECTION LOGIC ---

def signature_detection(payload):
    """Detects XSS using regex patterns."""
    patterns = [r"<script.*?>", r"javascript:", r"onload=", r"onerror=", r"<img.*?src="]
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

def anomaly_detection(payload):
    """Detects XSS based on statistical scoring (anomaly-based)."""
    special_chars = ['<', '>', '(', ')', '[', ']', '{', '}', '/', '\\', '\'', '"', ';', ':']
    score = 0
    if not payload:
        return False
    
    # Increase score for every special character found
    for char in payload:
        if char in special_chars:
            score += 1
            
    # If more than 15% of the string is special characters, flag it
    threshold = 0.15
    return (score / len(payload)) > threshold

def log_attack(payload, method, ip_address):
    """Saves the attack details to MongoDB Atlas."""
    attack_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "payload": payload,
        "method": method,
        "ip": ip_address,
        "status": "Blocked"
    }
    logs_collection.insert_one(attack_data)

# --- 3. ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        
        # Hybrid Detection
        is_sig = signature_detection(user_input)
        is_anom = anomaly_detection(user_input)
        
        if is_sig or is_anom:
            method = "Signature Match" if is_sig else "Anomaly Detected"
            log_attack(user_input, method, request.remote_addr)
            result = f"🚨 XSS Attack Blocked ({method})!"
        else:
            result = "✅ Safe input received."
            
    return render_template('xss_both_demo.html', result=result)

@app.route('/dashboard')
def dashboard():
    """Fetches all logs from MongoDB for display."""
    # .find({}, {'_id': 0}) hides MongoDB's internal ID
    # .sort("timestamp", -1) puts the newest attacks at the top
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
    return render_template('dashboard.html', logs=all_logs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
