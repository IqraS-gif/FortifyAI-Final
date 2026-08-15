"""
Live scan stepper verification — polls GET /api/scans/{id}/status
and records every distinct module transition from start to completed.
"""
import time
import requests

API = "http://127.0.0.1:8000"

print("Starting live scan via POST /api/scans ...")
r = requests.post(f"{API}/api/scans", json={"config_file": "config_final.yaml"})
r.raise_for_status()
scan_id = r.json()["scan_id"]
print(f"scan_id: {scan_id}\n")

seen_modules = []
last_module = None
tick = 0

while True:
    r = requests.get(f"{API}/api/scans/{scan_id}/status")
    r.raise_for_status()
    s = r.json()
    status = s["status"]
    mod = s["current_module"]
    tick += 1

    line = f"[{tick:>3}s] status={status:<10} module={str(mod):<22}"
    print(line)

    if mod and mod != last_module:
        seen_modules.append(mod)
        last_module = mod

    if status in ("completed", "failed"):
        print(f"\n=== FINAL STATUS: {status} ===")
        if s["error_message"]:
            print("error_message:", s["error_message"][:300])
        break

    time.sleep(1)

print("\n--- Module transition sequence ---")
for i, m in enumerate(seen_modules):
    print(f"  {i+1}. {m}")

ALL_9 = [
    "acl_fuzzer", "inversion", "poisoning", "drift", "probe",
    "dp_noise_injector", "acl_simulator", "collision_scorer", "poison_classifier"
]
missing = [m for m in ALL_9 if m not in seen_modules]
if missing:
    print(f"\n⚠  MISSING from trace: {missing}")
else:
    print("\n✅ All 9 modules appeared in the trace.")
