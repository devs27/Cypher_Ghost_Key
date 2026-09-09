"""
CYPHER GHOST KEY — VIRTUAL ATTACK 2: CLONE / IMPOSSIBLE TRAVEL ATTACK
Demonstrates defense against cloned cards.
An attacker clones a valid card and attempts to use it at Node B (Server Room)
almost immediately after the real owner scanned into Node A (Main Gate).
The physics / context-aware engine recognizes that a human cannot physically
travel between the two checkpoints in less than the threshold (5s), blocking the clone.
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

def make_event(node):
    ts = time.time()
    nonce = f"CLONE-{random.randint(100000, 999999)}-{time.time_ns()}"
    return {
        "node_id": node,
        "uid": UID,
        "ts": ts,
        "nonce": nonce,
        "sig": sign(node, UID, ts, nonce),
        "direction": "ENTRY" if node == "NODE_A" else "ACCESS"
    }

print("=" * 60)
print("  ATTACK 2: CLONE / IMPOSSIBLE TRAVEL SIMULATION")
print("=" * 60)
print(f"Target Server: {SERVER}")
print(f"Target UID: {UID}")
print()

# Step 1: Real owner scans into Node A (Main Gate)
print("[1] Real card scanned at Node A (Main Gate)...")
evt_a = make_event("NODE_A")
resp_a = requests.post(SERVER, json=evt_a, timeout=5)
print(f"    Status: {resp_a.status_code}")
print(f"    Response: {resp_a.json()}")

# Wait only 1 second (impossible travel time)
delay_sec = 1.0
print(f"\n[2] Waiting {delay_sec} second (Impossible travel threshold is 5s)...")
time.sleep(delay_sec)

# Step 2: Cloned card scanned at Node B (Server Room)
print("[3] Cloned card presented at Node B (Server Room)...")
evt_b = make_event("NODE_B")
resp_b = requests.post(SERVER, json=evt_b, timeout=5)
print(f"    Status: {resp_b.status_code}")
print(f"    Response: {resp_b.json()}")

print("\n" + "=" * 60)
print("VERDICT / ANALYSIS:")
if resp_b.status_code == 403 and "impossible travel" in resp_b.text.lower():
    print(">>> DEFENSE SUCCESSFUL! <<<")
    print("Security engine flagged impossible physical travel between Node A and Node B.")
    print("Clone / relay attack successfully thwarted!")
else:
    print("Response details:", resp_b.text)
print("=" * 60)