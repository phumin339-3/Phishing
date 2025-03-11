import pandas as pd

# โหลด data.csv
df = pd.read_csv("data.csv")

# ฟังก์ชันกำหนด Label (ใช้ข้อมูลจากฐานข้อมูลฟิชชิ่ง)
def assign_label(url):
    phishing_keywords = ["login", "secure", "verify", "bank", "account", "password", "update", "confirm"]
    if any(word in url.lower() for word in phishing_keywords):
        return "unsafe"
    return "safe"

# เพิ่มคอลัมน์ Label
df["label"] = df["url"].apply(assign_label)

# เลือกเฉพาะคอลัมน์ที่ต้องใช้ Train ML
ml_df = df[["domain_age_days", "special_chars_count", "redirected", "popup_detected", "new_tabs_opened", "label"]]

# บันทึกเป็นไฟล์ใหม่
ml_df.to_csv("ml_dataset.csv", index=False, encoding="utf-8")

print("✅ บันทึกไฟล์ `ml_dataset.csv` สำเร็จ! พร้อมใช้ Train Machine Learning")
