import time
import requests

API_URL = "http://127.0.0.1:8000"

print("1. Get configs")
r = requests.get(f"{API_URL}/api/configs")
print(r.json())

print("2. Start scan")
r = requests.post(f"{API_URL}/api/scans", json={"config_file": "config_final.yaml"})
scan_id = r.json()["scan_id"]
print("Scan ID:", scan_id)

print("3. Poll status")
while True:
    try:
        r = requests.get(f"{API_URL}/api/scans/{scan_id}/status")
        status = r.json()
        print("Status:", status)
        if status["status"] in ("completed", "failed"):
            break
    except Exception as e:
        print("Error polling:", e)
    time.sleep(5)

print("4. Get report")
r = requests.get(f"{API_URL}/api/scans/{scan_id}/report")
print("Report Keys:", r.json().keys())
if "overall_score" in r.json():
    print("Score:", r.json()["overall_score"]["overall_score"])
    print("Weights present:", "weights" in r.json()["overall_score"])
    print("Config file present:", r.json()["overall_score"].get("config_snapshot", {}).get("config_file"))

print("5. Get cached scans")
r = requests.get(f"{API_URL}/api/scans/cached")
print("Cached scans found:", len(r.json()))
if len(r.json()) > 0:
    print("Sample cached scan:", r.json()[0])
