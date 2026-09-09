"""
CYPHER GHOST KEY — SOC BACKEND SERVER
Points directly to the full security engine in app.py.
Ensures whether you run `python server.py` or `python app.py`,
the authentic database, cryptographic checks, and SOC features are active.
"""
try:
    from app import app, init_db, current_server_pin
except ImportError:
    from backend.app import app, init_db, current_server_pin


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" CYPHER GHOST KEY — SOC BACKEND ENGINE ACTIVE (server.py)")
    print(" Default Authorized Card: E2E93719 (Main Gate + Server Room)")
    print(" Server Room Default PIN:", current_server_pin)
    print(" Dashboard URL: http://0.0.0.0:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
