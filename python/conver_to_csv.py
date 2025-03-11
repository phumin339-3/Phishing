import json
import pandas as pd

# โหลดข้อมูลจาก data.json
with open("data.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# แปลงเป็น DataFrame
df = pd.DataFrame(data)

# บันทึกเป็น CSV (เก็บข้อมูลดิบ)
df.to_csv("data.csv", index=False, encoding="utf-8")

print("✅ บันทึกไฟล์ `data.csv` สำเร็จ!")

