"""
CYPHER GHOST KEY — VIRTUAL ATTACK 5: RELAY / LATENCY ATTACK
Demonstrates defense against signal relaying.
An attacker uses proxy hardware to relay an RFID signal over a long distance,
introducing transmission delays. The backend timestamp freshness window catches
the latency/delay and rejects the expired packet.
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
print("  ATTACK 5: RELAYED SIGNAL / STALE PACKET SIMULATION")
print("=" * 60)
print(f"Target Server: {SERVER}")
print(f"Testing with UID: {UID}")
print()

# Attacker relays packet with a 90-second delay
stale_ts = time.time() - 90.0
nonce = f"RELAY-{random.randint(10000, 99999)}"
sig = sign("NODE_A", UID, stale_ts, nonce)

payload = {
    "node_id": "NODE_A",
    "uid": UID,
    "ts": stale_ts,
    "nonce": nonce,
    "sig": sig,
    "direction": "AUTO"
}

print(f"[1] Sending packet with 90s latency (Freshness window: 30s)...")
resp = requests.post(SERVER, json=payload, timeout=5)
print(f"    Status: {resp.status_code}")
print(f"    Response: {resp.json()}")

print("\n" + "=" * 60)
print("VERDICT / ANALYSIS:")
if resp.status_code == 403 and "stale" in resp.text.lower():
    print(">>> DEFENSE SUCCESSFUL! <<<")
    print("The security engine detected the delayed/relayed packet and rejected access.")
else:
    print("Result:", resp.text)
print("=" * 60)

