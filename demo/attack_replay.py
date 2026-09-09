"""
CYPHER GHOST KEY — VIRTUAL ATTACK 1: REPLAY ATTACK
Demonstrates defense against intercepted and re-transmitted authentication tokens.
The attacker records a valid scan packet (nonce + HMAC + timestamp) and attempts
to replay it. The security engine catches that the cryptographic nonce was already
consumed and denies access immediately.
"""
import os
import time
import hmac
import hashlib
import random
import requests

SERVER = os.getenv("GHOSTKEY_EVENT_URL", "http://127.0.0.1:5000/api/event")
SECRET = os.getenv("GHOSTKEY_SECRET", "CypherGhostKey_2026_Secure_9f83xA72")
UID = "E2E93719"

def sign(node, uid, ts, nonce):
    payload = f"{node}|{uid}|{ts}|{nonce}"
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

print("=" * 60)
print("  ATTACK 1: REPLAY ATTACK SIMULATION")
print("=" * 60)
print(f"Target Server: {SERVER}")
print(f"Testing with Authorized UID: {UID}")
print()

# Step 1: Craft a legitimate signed packet
ts = time.time()
nonce = f"REPLAY-{random.randint(100000, 999999)}"
sig = sign("NODE_A", UID, ts, nonce)

payload = {
    "node_id": "NODE_A",
    "uid": UID,
    "ts": ts,
    "nonce": nonce,
    "sig": sig,
    "direction": "AUTO"
}

# Step 2: First transmission (Legitimate scan)
print("[1] Transmitting initial valid scan to Node A (Main Gate)...")
first = requests.post(SERVER, json=payload, timeout=5)
print(f"    Status: {first.status_code}")
print(f"    Response: {first.json()}")

time.sleep(1)

# Step 3: Second transmission with IDENTICAL nonce and signature (Attacker replay)
print("\n[2] Attacker replaying the exact same packet...")
second = requests.post(SERVER, json=payload, timeout=5)
print(f"    Status: {second.status_code}")
print(f"    Response: {second.json()}")

print("\n" + "=" * 60)
print("VERDICT / ANALYSIS:")
if second.status_code == 403 and "replay" in second.text.lower():
    print(">>> DEFENSE SUCCESSFUL! <<<")
    print("The security engine detected the reused nonce and blocked the replay.")
else:
    print("Warning: unexpected response:", second.text)
print("=" * 60)