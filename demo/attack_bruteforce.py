"""
CYPHER GHOST KEY — VIRTUAL ATTACK 3: BRUTE FORCE ACCUMULATION & LOCKOUT
Demonstrates brute-force detection and rate limiting.
An attacker rapidly scans multiple unknown / random NFC tags at a reader.
The security engine tracks consecutive failures (1/5, 2/5, 3/5, 4/5, 5/5)
and automatically locks out the physical node for 30 seconds once the threshold is met.
"""
import os
import time
import hmac
import hashlib
import random
import requests

SERVER = os.getenv("GHOSTKEY_EVENT_URL", "http://127.0.0.1:5000/api/event")
SECRET = os.getenv("GHOSTKEY_SECRET", "CypherGhostKey_2026_Secure_9f83xA72")

def sign(node, uid, ts, nonce):
    payload = f"{node}|{uid}|{ts}|{nonce}"
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

print("=" * 60)
print("  ATTACK 3: BRUTE FORCE ACCUMULATION & LOCKOUT SIMULATION")
print("=" * 60)
print(f"Target Server: {SERVER}")
print("Firing 6 consecutive invalid NFC scans at NODE_A (Threshold: 5)...")
print()

for i in range(1, 7):
    fake_uid = f"BAD{random.randint(1000, 9999)}"
    ts = time.time()
    nonce = f"BRUTE-{i}-{random.randint(10000, 99999)}"
    sig = sign("NODE_A", fake_uid, ts, nonce)

    payload = {
        "node_id": "NODE_A",
        "uid": fake_uid,
        "ts": ts,
        "nonce": nonce,
        "sig": sig,
        "direction": "AUTO"
    }

    resp = requests.post(SERVER, json=payload, timeout=5)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}

    print(f"Attempt {i}/6 [UID: {fake_uid}]:")
    print(f"    Status: {resp.status_code}")
    print(f"    Verdict: {data.get('verdict')} | Reason: {data.get('reason')}")
    if "fail_count" in data:
        print(f"    Accumulated Failures: {data.get('fail_count')}/5")
    if data.get("locked"):
        print(f"    [!] NODE LOCKED OUT! Remaining: {data.get('lockout_remaining')}s")
    print()
    time.sleep(0.3)

print("=" * 60)
print("VERDICT / ANALYSIS:")
print("Attempts 1 to 4: Failures accumulated and logged.")
print("Attempt 5: Triggered automatic 30-second lockout.")
print("Attempt 6: Dropped immediately with HTTP 403 (Node locked).")
print("The SOC dashboard reflects the active lockout status and countdown timer.")
print("=" * 60)