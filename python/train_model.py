import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# โหลด dataset
df = pd.read_csv("ml_dataset.csv")

# แปลง Label เป็นตัวเลข (safe = 0, unsafe = 1)
df["label"] = df["label"].map({"safe": 0, "unsafe": 1})

# เลือก Features และ Target
X = df.drop(columns=["label"])
y = df["label"]

# แบ่งข้อมูล Train/Test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train โมเดล Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ทดสอบความแม่นยำ
y_pred = model.predict(X_test)
print(f"🎯 Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

# บันทึกโมเดล
joblib.dump(model, "phishing_model.pkl")

print("✅ บันทึกโมเดล `phishing_model.pkl` สำเร็จ!")
