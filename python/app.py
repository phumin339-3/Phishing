from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import json
import requests
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__, template_folder="templates")  # ✅ ตั้งค่า template folder

# ✅ โหลดโมเดล Machine Learning
model = joblib.load("phishing_model.pkl")

# ✅ ฟังก์ชันตรวจสอบ OpenPhish
def check_openphish(url):
    try:
        with open("database/openphish.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        parsed_url = urlparse(url)
        normalized_url = parsed_url.netloc.lower() + parsed_url.path.lower()

        for entry in data:
            if "url" in entry:
                stored_url = urlparse(entry["url"]).netloc.lower() + urlparse(entry["url"]).path.lower()
                if stored_url == normalized_url:
                    print(f"⚠️ พบ URL ใน OpenPhish: {stored_url}")  # Debug
                    return "unsafe"

        print(f"✅ URL ไม่พบใน OpenPhish: {normalized_url}")  # Debug
        return "safe"
    except Exception as e:
        print(f"❌ OpenPhish JSON error: {e}")
        return "unknown"

# ✅ ฟังก์ชันใช้ Machine Learning ทำนายผล
def check_ml_model(url):
    features = np.array([[1000, 5, 1, 0, 0]])  # ค่าตัวอย่างที่ต้องปรับ
    prediction = model.predict(features)[0]
    return "unsafe" if prediction == 1 else "safe"

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")  # ✅ โหลดหน้า index.html

@app.route("/check_url/", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    results = {
        "ML Model": check_ml_model(url),
        "OpenPhish": check_openphish(url),
        # ❗ ต้องแน่ใจว่า `check_phishtank`, `check_google_safe_browsing`, etc. ถูก import และมีฟังก์ชัน
    }

    if "unsafe" in results.values():
        final_result = "unsafe"
    else:
        final_result = "safe"

    print(f"🔍 URL: {url}, Result: {final_result}, Details: {results}")  # Debug
    return jsonify({"url": url, "result": final_result, "details": results})

if __name__ == "__main__":
    app.run(debug=True)
