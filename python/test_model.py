import joblib
import pandas as pd
import requests
from urllib.parse import urlparse

# โหลดโมเดล
model = joblib.load("phishing_model.pkl")

def extract_features(url):
    """ ดึงฟีเจอร์จาก URL """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # เช็ค Redirect
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        redirected = len(response.history) > 0
    except:
        redirected = False

    return pd.DataFrame([{
        "domain_age_days": 1000,  # ตัวอย่างค่า
        "special_chars_count": 5,  # นับจำนวนอักขระพิเศษ
        "redirected": int(redirected),
        "popup_detected": 0,
        "new_tabs_opened": 0
    }])

# ทดสอบโมเดล
test_url = "http://example.com"
features = extract_features(test_url)
prediction = model.predict(features)[0]

print(f"🔍 URL: {test_url} → {'unsafe' if prediction == 1 else 'safe'}")
