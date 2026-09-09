"""
CYPHER GHOST KEY — VIRTUAL ATTACK 4: STOLEN CARD (POSSESSION ALONE IS INSUFFICIENT)
Demonstrates defense against a physically stolen badge.
Even if an attacker possesses a genuine, authorized card (E2E93719) with Server Room
privileges, physical possession alone cannot open the door:
1. Physical perimeter context: If the card was never scanned into Main Gate, access is denied.
2. Second-Factor Verification: Even when inside, the Server Room requires a separate PIN
   entered via the dashboard operator. The servo remains firmly locked until PIN challenge passes.
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
print("  ATTACK 4: STOLEN CARD 2FA PIN DEFENSE SIMULATION")
print("=" * 60)
print(f"Target Server: {SERVER}")
print(f"Authorized Card: {UID}")
print()

# Case A: Attacker attempts to scan stolen card directly at Server Room
# without entering the building perimeter first
print("[Case A] Attacker scans card directly at Server Room (Bypassing Main Gate)...")
ts = time.time()
nonce = f"STOLEN-A-{random.randint(10000, 99999)}"
payload_a = {
    "node_id": "NODE_B",
    "uid": UID,
    "ts": ts,
    "nonce": nonce,
    "sig": sign("NODE_B", UID, ts, nonce),
    "direction": "ACCESS"
}

resp_a = requests.post(SERVER, json=payload_a, timeout=5)
print(f"    Status: {resp_a.status_code}")
print(f"    Response: {resp_a.json()}")

# Case B: Attacker stole card after owner entered building, now tapping Server Room
print("\n[Case B] Person legitimately entered building; now tapping Server Room...")
# First scan into Main Gate legitimately
ts_gate = time.time()
nonce_gate = f"GATE-{random.randint(10000, 99999)}"
requests.post(SERVER, json={
    "node_id": "NODE_A",
    "uid": UID,
    "ts": ts_gate,
    "nonce": nonce_gate,
    "sig": sign("NODE_A", UID, ts_gate, nonce_gate),
    "direction": "ENTRY"
}, timeout=5)

# Wait 6 seconds to pass impossible travel window
time.sleep(6)

# Now tap at Server Room
ts_b = time.time()
nonce_b = f"STOLEN-B-{random.randint(10000, 99999)}"
payload_b = {
    "node_id": "NODE_B",
    "uid": UID,
    "ts": ts_b,
    "nonce": nonce_b,
    "sig": sign("NODE_B", UID, ts_b, nonce_b),
    "direction": "ACCESS"
}

resp_b = requests.post(SERVER, json=payload_b, timeout=5)
data_b = resp_b.json()
print(f"    Status: {resp_b.status_code}")
print(f"    Response: {data_b}")

print("\n" + "=" * 60)
print("VERDICT / ANALYSIS:")
if data_b.get("verdict") == "PIN_REQUIRED":
    print(">>> DEFENSE SUCCESSFUL! <<<")
    print("Possession alone did NOT grant access.")
    print(f"The system challenged for a PIN with Request ID: {data_b.get('request_id')}")
    print("The servo door remains locked until operator enters PIN on dashboard.")
else:
    print("Result:", resp_b.text)
print("=" * 60)