import json
import os

file_path = "database/data.json"  # แก้ไขเป็นพาธของไฟล์

# โหลดข้อมูลเดิม ถ้ามี
if os.path.exists(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            existing_data = json.load(file)
    except json.JSONDecodeError:
        print("⚠️ JSON Decode Error: Database file is corrupted, creating a new one.")
        existing_data = []
else:
    existing_data = []

# ✅ ทดสอบข้อมูลก่อนบันทึก
test_data = {
    "url": "https://example.com",
    "timestamp": "2025-02-27 12:00:00",
    "ssl_valid": True,
    "domain_age_days": 365,
    "special_chars_count": 2,
    "redirected": False,
    "popup_detected": False,
    "javascript_alert_detected": None,
    "new_tabs_opened": 0,
}

# ✅ ตรวจสอบว่าข้อมูลถูกต้องก่อนบันทึก
print("📂 Data before saving:", json.dumps(test_data, indent=4))

# เพิ่มข้อมูลใหม่
existing_data.append(test_data)

# ✅ Debug ตรวจสอบการเขียนไฟล์
try:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4)
    print("✅ Data saved successfully!")
except Exception as e:
    print(f"❌ Error saving data: {e}")

# ✅ ตรวจสอบว่าไฟล์ถูกสร้างและแก้ไขหรือไม่
if os.path.exists(file_path):
    print(f"📁 File exists: {file_path}")
    print(f"📏 File size: {os.path.getsize(file_path)} bytes")
else:
    print(f"⚠️ File not found: {file_path}")
