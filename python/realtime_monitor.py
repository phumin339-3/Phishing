import threading
import time
from python.Event import check_phishing_all_sources
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# ตั้งค่า WebDriver
webdriver_path = "C:\\Users\\marut\\Downloads\\Webdriver\\chromedriver.exe"
chrome_options = Options()
chrome_options.add_experimental_option("detach", True)

service = Service(executable_path=webdriver_path)
driver = webdriver.Chrome(service=service, options=chrome_options)

def monitor_website(url):
    """ตรวจจับ URL แบบ Real-time"""
    driver.get(url)
    time.sleep(3)

    while True:
        print(f"🔍 Scanning: {url}")
        status, results = check_phishing_all_sources(url)
        print(f"🛡️ Results: {results}")
        time.sleep(10)  # ✅ ตรวจทุก 10 วินาที

def start_monitoring(url):
    """เริ่ม Real-time Monitoring บน Thread แยก"""
    monitoring_thread = threading.Thread(target=monitor_website, args=(url,))
    monitoring_thread.daemon = True
    monitoring_thread.start()
    print("✅ Real-time monitoring started.")

# ใช้งาน
if __name__ == "__main__":
    test_url = "https://dmarket.com/"
    start_monitoring(test_url)
