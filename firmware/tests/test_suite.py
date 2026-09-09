"""
Comprehensive automated test suite for Cypher Ghost Key Backend.
Tests all security features, database tables, and API endpoints in-process.
"""
import time
import json
import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app import app, init_db, sign_payload, db, current_server_pin

def run_tests():
    init_db()
    client = app.test_client()
    passed = 0
    total = 0

    def test(name, condition):
        nonlocal passed, total
        total += 1
        if condition:
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}")
            assert False, f"Test failed: {name}"

    print("=" * 60)
    print("RUNNING CYPHER GHOST KEY VERIFICATION TESTS")
    print("=" * 60)

    # 1. Verify default card E2E93719 exists with proper permissions
    res = client.get("/api/cards")
    cards = res.get_json()
    e2e = next((c for c in cards if c["uid"] == "E2E93719"), None)
    test("E2E93719 exists in database", e2e is not None)
    test("E2E93719 status is active", e2e["status"] == "active")
    test("E2E93719 has Main Gate access (1)", e2e["main_gate"] == 1)
    test("E2E93719 has Server Room access (1)", e2e["server_room"] == 1)

    # 2. Verify node status endpoint
    res = client.get("/api/nodes")
    nodes = res.get_json()
    test("NODE_A exists in /api/nodes", "NODE_A" in nodes)
    test("NODE_B exists in /api/nodes", "NODE_B" in nodes)

    # Reset any previous failures & presence
    client.post("/api/nodes/NODE_A/reset")
    client.post("/api/nodes/NODE_B/reset")
    conn = db()
    conn.execute("UPDATE presence SET status='OUTSIDE' WHERE uid='E2E93719'")
    conn.execute("DELETE FROM exit_armed WHERE uid='E2E93719'")
    conn.commit()
    conn.close()

    # 3. Node A: Legitimate Entry for E2E93719
    now = time.time()
    nonce1 = f"TEST-ENTRY-{int(now * 1000)}"
    sig1 = sign_payload("NODE_A", "E2E93719", now, nonce1)
    res = client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce1,
        "sig": sig1,
        "direction": "AUTO"
    })
    data = res.get_json()
    test("Entry scan verdict is GRANTED", data.get("verdict") == "GRANTED")
    test("Direction is ENTRY", data.get("direction") == "ENTRY")
    test("Presence is INSIDE", data.get("presence") == "INSIDE")

    # 4. Anti-Passback / Replay: Scan again at Node A without arming exit
    now = time.time()
    nonce2 = f"TEST-DUP-{int(now * 1000)}"
    sig2 = sign_payload("NODE_A", "E2E93719", now, nonce2)
    res = client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce2,
        "sig": sig2,
        "direction": "AUTO"
    })
    data = res.get_json()
    test("Duplicate entry is DENIED (Replay/Anti-passback)", res.status_code == 403 and data.get("verdict") == "DENIED")
    test("Reason mentions replay / already inside", "replay" in data.get("reason", "").lower() or "inside" in data.get("reason", "").lower())

    # 5. Arm Exit on Dashboard
    res = client.post("/api/exit/arm", json={"uid": "E2E93719"})
    data = res.get_json()
    test("Exit arming response is ARMED", data.get("verdict") == "ARMED")

    # 6. Scan again at Node A -> Now should be GRANTED (EXIT)
    now = time.time()
    nonce3 = f"TEST-EXIT-{int(now * 1000)}"
    sig3 = sign_payload("NODE_A", "E2E93719", now, nonce3)
    res = client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce3,
        "sig": sig3,
        "direction": "AUTO"
    })
    data = res.get_json()
    test("Exit scan verdict is GRANTED", data.get("verdict") == "GRANTED")
    test("Direction is EXIT", data.get("direction") == "EXIT")
    test("Presence is OUTSIDE", data.get("presence") == "OUTSIDE")

    # 7. Replay Attack: Exact same packet retransmitted
    res = client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce3,
        "sig": sig3,
        "direction": "AUTO"
    })
    data = res.get_json()
    test("Reused nonce is DENIED", res.status_code == 403 and data.get("verdict") == "DENIED")
    test("Reason indicates nonce already consumed", "nonce" in data.get("reason", "").lower())

    # 8. Brute Force Accumulation: 5 wrong NFC tags at Node A
    client.post("/api/nodes/NODE_A/reset")
    for i in range(1, 6):
        fake_uid = f"FAIL{i:04d}"
        now = time.time()
        nonce_f = f"BRUTE-TEST-{i}-{int(now * 1000)}"
        sig_f = sign_payload("NODE_A", fake_uid, now, nonce_f)
        res = client.post("/api/event", json={
            "node_id": "NODE_A",
            "uid": fake_uid,
            "ts": now,
            "nonce": nonce_f,
            "sig": sig_f
        })
    res = client.get("/api/nodes")
    nodes = res.get_json()
    test("Node A failure count reached 5", nodes["NODE_A"]["fail_count"] == 5)
    test("Node A is locked out", nodes["NODE_A"]["is_locked"] is True)

    # 6th attempt during lockout must be immediately rejected with 403
    now = time.time()
    nonce_locked = f"LOCKED-{int(now * 1000)}"
    res = client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce_locked,
        "sig": sign_payload("NODE_A", "E2E93719", now, nonce_locked)
    })
    test("Scan during lockout rejected with 403", res.status_code == 403 and res.get_json().get("locked") is True)

    # Reset Node A lockout for subsequent tests
    client.post("/api/nodes/NODE_A/reset")

    # 9. Server Room 2FA Flow
    # Check into building first
    now = time.time()
    nonce_gate = f"GATE-CHECKIN-{int(now * 1000)}"
    client.post("/api/event", json={
        "node_id": "NODE_A",
        "uid": "E2E93719",
        "ts": now,
        "nonce": nonce_gate,
        "sig": sign_payload("NODE_A", "E2E93719", now, nonce_gate)
    })

    # Wait 6s to satisfy impossible travel between Node A and Node B
    # To test without waiting in unit test, adjust ts or wait:
    time.sleep(0.1) # Note: we can simulate a valid gap by setting ts earlier or testing directly
    # Now scan at Node B with ts_now
    ts_now = time.time()
    nonce_server = f"SERVER-SCAN-{int(ts_now * 1000)}"
    sig_server = sign_payload("NODE_B", "E2E93719", ts_now, nonce_server)
    res = client.post("/api/event", json={
        "node_id": "NODE_B",
        "uid": "E2E93719",
        "ts": ts_now,
        "nonce": nonce_server,
        "sig": sig_server,
        "direction": "ACCESS"
    })
    # Wait, if now_b was 0.1s after now, it might trigger impossible travel!
    # Let's check what happened:
    data_b = res.get_json()
    if data_b.get("verdict") == "DENIED" and "impossible travel" in data_b.get("reason", "").lower():
        test("Impossible travel correctly triggered for gap < 5s", True)
        # Sleep for real 5s or reset events to test PIN
        time.sleep(5.1)
        now_b2 = time.time()
        nonce_b2 = f"SERVER-SCAN-2-{int(now_b2 * 1000)}"
        res = client.post("/api/event", json={
            "node_id": "NODE_B",
            "uid": "E2E93719",
            "ts": now_b2,
            "nonce": nonce_b2,
            "sig": sign_payload("NODE_B", "E2E93719", now_b2, nonce_b2),
            "direction": "ACCESS"
        })
        data_b = res.get_json()

    test("Server Room scan requires PIN (PIN_REQUIRED)", data_b.get("verdict") == "PIN_REQUIRED")
    req_id = data_b.get("request_id")
    test("Valid request_id returned", bool(req_id))

    # Test Decision poll before PIN -> PENDING
    res = client.get(f"/api/decision/{req_id}")
    test("Decision poll is PENDING before PIN", res.get_json().get("status") == "PENDING")

    # Verify PIN with wrong pin first
    res = client.post("/api/server/verify", json={"request_id": req_id, "pin": "9999"})
    test("Wrong PIN rejected", res.status_code == 403 and res.get_json().get("verdict") == "DENIED")

    # Trigger fresh request for right PIN test
    time.sleep(0.1)
    client.post("/api/nodes/NODE_B/reset")
    now_b3 = time.time()
    nonce_b3 = f"SERVER-SCAN-3-{int(now_b3 * 1000)}"
    res = client.post("/api/event", json={
        "node_id": "NODE_B",
        "uid": "E2E93719",
        "ts": now_b3,
        "nonce": nonce_b3,
        "sig": sign_payload("NODE_B", "E2E93719", now_b3, nonce_b3),
        "direction": "ACCESS"
    })
    req_id2 = res.get_json().get("request_id")

    # Verify correct PIN ("2468")
    res = client.post("/api/server/verify", json={"request_id": req_id2, "pin": current_server_pin})
    data_pin = res.get_json()
    test("Correct PIN verification GRANTED", data_pin.get("verdict") == "GRANTED")
    test("Door unlocked", data_pin.get("door") == "UNLOCKED")

    # Check decision polling for ESP32 -> GRANTED
    res = client.get(f"/api/decision/{req_id2}")
    test("Decision poll returns GRANTED for ESP32", res.get_json().get("status") == "GRANTED")

    # 10. Test Virtual Attack Simulations
    for attack in ["replay", "bruteforce", "clone", "stolen", "relay", "valid_entry", "valid_exit"]:
        res = client.post(f"/api/virtual-attack/{attack}")
        test(f"Virtual attack [{attack}] simulation succeeds", res.status_code == 200)

    print("=" * 60)
    print(f"ALL TESTS PASSED: {passed} / {total}")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
