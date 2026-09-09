import time, hashlib, hmac as hmac_mod, requests, json

SHARED_SECRET = "ghostkey_secret_2025"
BASE = "http://127.0.0.1:5000"

def scan(uid, node_id):
    ts = int(time.time())
    nonce = f"test_{ts}"
    payload = f"{uid}|{node_id}|{ts}|{nonce}"
    mac = hmac_mod.new(SHARED_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    body = {"uid": uid, "node_id": node_id, "timestamp": ts, "nonce": nonce, "hmac": mac}
    r = requests.post(f"{BASE}/api/scan", json=body)
    print(f"[{node_id}] {uid} -> {r.status_code}: {r.json()}")
    return r.json()

# Test E2E93719 at Node B (should get GRANTED directly)
print("=== Testing E2E93719 at NODE_B (admin bypass) ===")
scan("E2E93719", "NODE_B")
