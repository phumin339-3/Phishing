import requests
import json
import time
import os
import ssl
import socket
import re
import atexit
from datetime import datetime
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

# ✅ ตั้งค่า WebDriver
webdriver_path = "C:\\Users\\marut\\Downloads\\Webdriver\\chromedriver.exe"
chrome_options = Options()
chrome_options.add_experimental_option("detach", True)

service = Service(executable_path=webdriver_path)
driver = webdriver.Chrome(service=service, options=chrome_options)

# ✅ API Keys
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyAOY26ThIRKUvkQeIrGUKjTmLDvCob10DY"
VIRUSTOTAL_API_KEY = "c64e4f214217d6933a538f881882fdb09cf11ea5691ba0588a24dda69b891a0a"

# ✅ VirusTotal API
def check_virustotal(url):
    """ ตรวจสอบ URL ผ่าน VirusTotal API """
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    try:
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        analysis_id = result["data"]["id"]

        # ดึงผลลัพธ์การสแกน
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(report_url, headers=headers)
        report_data = response.json()

        if report_data["data"]["attributes"]["stats"]["malicious"] > 0:
            return "unsafe"
        return "safe"
    except Exception as e:
        print(f"❌ VirusTotal API error: {e}")
        return "unknown"

# ✅ Google Safe Browsing API
def check_google_safe_browsing(url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "phishing_detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(api_url, json=payload, params={"key": GOOGLE_SAFE_BROWSING_API_KEY})
        response.raise_for_status()
        data = response.json()
        return "unsafe" if "matches" in data else "safe"
    except Exception as e:
        print(f"❌ Google Safe Browsing error: {e}")
        return "unknown"

# ✅ URLhaus API
def check_urlhaus_api(url):
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        response = requests.post(api_url, data={"url": url}, timeout=10)
        response.raise_for_status()
        data = response.json()
        return "unsafe" if data.get("query_status") == "malicious" else "safe"
    except Exception as e:
        print(f"❌ URLhaus API error: {e}")
        return "unknown"

# ✅ URLhaus JSON
def check_urlhaus_json(url):
    try:
        with open("database/urlhaus.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        malicious_urls = {entry["url"] for sublist in data.values() for entry in sublist if "url" in entry}
        return "unsafe" if url in malicious_urls else "safe"
    except Exception as e:
        print(f"❌ URLhaus JSON error: {e}")
        return "unknown"

# ✅ OpenPhish JSON
def check_openphish(url):
    try:
        with open("database/openphish.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        parsed_url = urlparse(url)
        normalized_url = parsed_url._replace(scheme="http", fragment="").geturl().strip().lower()  # เอา # ออก

        print(f"🔎 Checking OpenPhish for: {normalized_url}")  # ✅ Debug URL

        for entry in data:
            if "url" in entry:
                stored_url = urlparse(entry["url"].strip().lower())._replace(fragment="").geturl()  # เอา # ออก
                if stored_url == normalized_url:
                    print(f"⚠️ Matched OpenPhish: {stored_url}")  # ✅ Debug ถ้าพบ
                    return "unsafe"

        print(f"✅ Not found in OpenPhish: {normalized_url}")  # ✅ Debug ถ้าไม่เจอ
        return "safe"
    except Exception as e:
        print(f"❌ OpenPhish JSON error: {e}")
        return "unknown"


# ✅ ฟังก์ชันเช็ค URL ในฐานข้อมูล PhishTank
def check_phishtank(url):
    try:
        with open("database/phishtank.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        # ✅ ตัด scheme (http/https) และ www. ออก + ตัด / ท้าย URL ออก
        parsed_url = urlparse(url.strip().lower())
        normalized_url = f"{parsed_url.netloc.replace('www.', '')}{parsed_url.path}".rstrip("/")
        
        print(f"🔎 Checking PhishTank for: {normalized_url}")  # ✅ Debug URL ที่กำลังตรวจสอบ

        for entry in data:
            if "url" in entry:
                # ✅ Normalize URL จากฐานข้อมูล
                parsed_stored_url = urlparse(entry["url"].strip().lower())
                stored_url = f"{parsed_stored_url.netloc.replace('www.', '')}{parsed_stored_url.path}".rstrip("/")


                if stored_url == normalized_url:
                    print(f"⚠️ Matched PhishTank: {normalized_url}")  # ✅ พบ URL ในฐานข้อมูล
                    return "unsafe"

        print(f"✅ Not found in PhishTank: {normalized_url}")  # ✅ ไม่พบ URL ในฐานข้อมูล
        return "safe"
    except Exception as e:
        print(f"❌ PhishTank JSON error: {e}")
        return "unknown"

# ✅ รวมทุก API และฐานข้อมูล JSON
def check_phishing_all_sources(url):
    results = {
        "Google Safe Browsing": check_google_safe_browsing(url),
        "VirusTotal": check_virustotal(url),
        "OpenPhish": check_openphish(url),
        "URLhaus API": check_urlhaus_api(url),
        "URLhaus JSON": check_urlhaus_json(url),
        "PhishTank": check_phishtank(url)
    }
    return "unsafe" if "unsafe" in results.values() else "safe", results

# ✅ อัปเดตฐานข้อมูลอัตโนมัติ
def update_databases():
    sources = {
        "openphish": "https://openphish.com/feed.txt",
        "urlhaus": "https://urlhaus.abuse.ch/downloads/json/"
    }
    for name, url in sources.items():
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.text if name == "openphish" else response.json()
            with open(f"database/{name}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            print(f"✅ {name.capitalize()} database updated.")
        except Exception as e:
            print(f"❌ Error updating {name}: {e}")

def check_ssl_certificate(domain):
    """ ตรวจสอบ SSL Certificate ของโดเมน """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"✅ SSL Certificate is valid for domain: {domain}")
                return cert
    except Exception as e:
        print(f"❌ SSL Certificate error for domain {domain}: {e}")
        return None

def check_domain_age(domain):
    """ ตรวจสอบอายุของโดเมนผ่าน Whois API """
    api_key = "at_7GUYm4WTUlLOQN1Ate1CZlcgpYqeK"  # 🔴 เปลี่ยนเป็น API Key จริงจาก WhoisXMLAPI
    try:
        response = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService", params={
            "domainName": domain,
            "apiKey": "at_7GUYm4WTUlLOQN1Ate1CZlcgpYqeK",
            "outputFormat": "JSON"
        })
        response.raise_for_status()
        data = response.json()
        creation_date = data.get("WhoisRecord", {}).get("registryData", {}).get("createdDate")
        if creation_date:
            age_days = (datetime.now() - datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%SZ")).days
            print(f"📅 Domain creation date: {creation_date} (Age: {age_days} days)")
            return age_days
        else:
            print("⚠️ Unable to retrieve domain age.")
            return None
    except Exception as e:
        print(f"❌ Error checking domain age for {domain}: {e}")
        return None

# ✅ นิยาม pattern เพื่อตรวจจับอักขระพิเศษ
special_characters_pattern = re.compile(r"[-._~:/?#@!$&'()*+,;=%]")

def analyze_url(url):
    """ วิเคราะห์ข้อมูลพื้นฐานของ URL """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_length = len(domain)

    # ✅ ตรวจจับตัวอักษรพิเศษ
    special_chars = special_characters_pattern.findall(url)
    special_chars_count = len(special_chars)

    # ✅ ตรวจสอบคำที่น่าสงสัยใน URL
    suspicious_keywords = ["login", "secure", "verify", "bank", "account", "password", "update", "confirm"]
    found_suspicious_keywords = [word for word in suspicious_keywords if word in url.lower()]
    contains_suspicious_keywords = bool(found_suspicious_keywords)

    analysis_result = {
        "url_length": len(url),
        "domain_length": domain_length,
        "special_chars_count": special_chars_count,
        "special_chars": special_chars,  # ✅ แสดงอักขระพิเศษที่พบ
        "contains_suspicious_keywords": contains_suspicious_keywords,
        "suspicious_keywords_found": found_suspicious_keywords  # ✅ แสดงคำที่น่าสงสัย
    }

    # ✅ แสดงรายละเอียดแบบอ่านง่าย
    print("\n🔍 **URL Analysis Details**")
    print(f"🔗 URL: {url}")
    print(f"📏 URL Length: {analysis_result['url_length']} characters")
    print(f"🏠 Domain: {domain} (Length: {analysis_result['domain_length']} characters)")
    print(f"🔣 Special Characters: {analysis_result['special_chars_count']} found ({', '.join(analysis_result['special_chars'])})" if analysis_result['special_chars_count'] > 0 else "🔣 No special characters detected.")
    
    if analysis_result["contains_suspicious_keywords"]:
        print(f"⚠️ Suspicious Keywords Detected: {', '.join(analysis_result['suspicious_keywords_found'])}")
    else:
        print("✅ No suspicious keywords found.")

    return analysis_result

def detect_cookie_popup():
    """ ตรวจจับ Cookie Consent Popup โดยใช้หลายวิธี """
    try:
        print("🔎 Checking for Cookie Consent Popup...")

        # ✅ ตรวจจับ <mat-dialog-container> (Angular Material Dialog)
        popup = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.XPATH, "//mat-dialog-container | //div[contains(@class, 'cookie')] | //div[contains(text(), 'Your Privacy Matters')]"))
        )
        print("✅ Cookie Consent Popup detected!")

        return True  # พบ Popup
    except Exception:
        print("⚠️ No Cookie Consent Popup detected.")
        return False  # ไม่พบ Popup



# ✅ ตั้งค่า URL ทดสอบ
test_url = "https://dmarket.com/"

# ✅ วิเคราะห์ URL
analysis_result = analyze_url(test_url)
print("🔍 URL Analysis Result:", analysis_result)

try:
    # ✅ ใช้งาน WebDriver ไปยัง URL
    driver.get(test_url)
    time.sleep(3)

   # ✅ ตรวจจับ Cookie Consent Popup
    has_popup = detect_cookie_popup()

    # ✅ แสดงผล
    if has_popup:
        print("⚠️ Found Cookie Consent Popup")
    else:
        print("✅ Not Found Cookie Consent Popup")

    previous_url = driver.current_url
    previous_windows = driver.window_handles  # ตรวจจับหน้าต่างที่มีอยู่ก่อน 

    print("🔄 Monitoring started. Press Ctrl+C to stop.")

    while True:
        current_url = driver.current_url  # ✅ ใช้ current_url เป็นตัวหลัก
        domain = urlparse(current_url).netloc
        print(f"🌐 Monitoring domain: {domain}")

        # ✅ ตรวจสอบฟิชชิ่งจาก API
        phishing_status, api_results = check_phishing_all_sources(current_url)
        print(f"🛡️ Phishing detection results: {api_results}")

        time.sleep(10)  # ✅ เช็คทุก 10 วินาที

        # ✅ ตรวจสอบ SSL และอายุโดเมน
        check_ssl_certificate(domain)
        check_domain_age(domain)

        # ✅ ตรวจสอบ Redirect
        if current_url != previous_url:
            print(f"🔄 Redirected to: {current_url}")
            previous_url = current_url
        else:
            print(f"✅ No redirect detected. Current URL: {current_url}")

        # ✅ ตรวจจับ HTML Pop-up
        try:
            pop_up = WebDriverWait(driver, 2).until(
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'sign in') or contains(text(), 'alert')]"))
            )
            print("⚠️ HTML Pop-up detected.")
        except:
            print("✅ No HTML Pop-up detected.")

        # ✅ ตรวจจับ JavaScript Alert
        try:
            WebDriverWait(driver, 2).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            print(f"⚠️ JavaScript Alert detected: {alert.text}")
            alert.accept()
        except:
            print("✅ No JavaScript Alert detected.")

        # ✅ ตรวจจับการเปิดหน้าต่าง/แท็บใหม่
        current_windows = driver.window_handles
        if len(current_windows) > len(previous_windows):
            new_window_count = len(current_windows) - len(previous_windows)
            print(f"⚠️ New window/tab detected: {new_window_count} new tab(s) opened.")
            previous_windows = current_windows  # อัปเดตรายการหน้าต่าง

        # ✅ ใช้พาธที่ถูกต้องสำหรับ data.json
        file_path = os.path.join(os.getcwd(), "database", "data.json")

        # ✅ ตรวจสอบว่ามี database/ หรือไม่ ถ้าไม่มีให้สร้าง
        if not os.path.exists("database"):
            os.makedirs("database")

        # ✅ โหลด data.json ถ้ามีอยู่แล้ว
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    existing_data = json.load(file)  # ✅ โหลดข้อมูลเก่า
                except json.JSONDecodeError:
                    print("⚠️ JSON Decode Error: Creating a new empty file.")
                    existing_data = []
        else:
            existing_data = []

        # ✅ ผลการตรวจจับฟิชชิ่ง
        phishing_detection_results = api_results  # ✅ ใช้ค่าจริงที่ได้จาก API

        # ✅ ข้อมูลใหม่ที่ต้องเพิ่ม (ใช้ current_url)
        result_data = {
            "url": current_url,  # ✅ ใช้ current_url แทนการกำหนด URL ซ้ำ
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_valid": check_ssl_certificate(domain) is not None,  # ✅ ถ้า SSL ใช้ได้ -> True, ถ้าไม่ใช้ได้ -> False
            "domain_age_days": check_domain_age(domain),
            "special_chars_count": len(special_characters_pattern.findall(current_url)),
            "redirected": current_url != test_url,
            "popup_detected": pop_up if "pop_up" in locals() else False,
            "javascript_alert_detected": alert.text if "alert" in locals() else None,
            "new_tabs_opened": len(current_windows) - len(previous_windows) if len(current_windows) > len(previous_windows) else 0,
            "phishing_detection_results": phishing_detection_results  # ✅ เพิ่มผลการตรวจจับฟิชชิ่ง
        }

        # ✅ อัปเดตข้อมูลถ้ามี URL นี้อยู่แล้ว
        found = False
        for index, entry in enumerate(existing_data):
            if entry["url"] == current_url:
                existing_data[index] = result_data  # ✅ แทนที่ข้อมูลเก่าด้วยข้อมูลใหม่
                found = True
                break

        # ✅ ถ้าไม่พบ URL เดิม ให้เพิ่มเป็นข้อมูลใหม่
        if not found:
            existing_data.append(result_data)

        # ✅ บันทึกใหม่แบบ JSON ลิสต์
        print("📂 Data before saving:", json.dumps(existing_data, indent=4))  # ✅ Debug
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)

        print(f"✅ Data saved successfully in {file_path}!")

        time.sleep(10)  # ✅ เช็คทุก 10 วินาที

except KeyboardInterrupt:
    print("\n🛑 Monitoring stopped by user.")

    # ✅ บันทึกผลลัพธ์ก่อนออก โดยใช้ file_path ที่ถูกต้อง
    if existing_data:
        with open(file_path, "w", encoding="utf-8") as file:  # ✅ ใช้ file_path ที่ถูกต้อง
            json.dump(existing_data, file, indent=4)
        print(f"✅ Data saved successfully in {file_path} before exit.")

except Exception as e:
    print(f"❌ An error occurred: {e}")

finally:
    print("🛑 WebDriver is still running. Manually close it when done.")