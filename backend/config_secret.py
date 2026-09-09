# ============================================================
# CYPHER GHOST KEY - BACKEND SECURITY CONFIGURATION
# ============================================================

# IMPORTANT:
# This secret must be IDENTICAL to the SHARED_SECRET
# in BOTH ESP32 config.h files.

SHARED_SECRET = "CypherGhostKey_2026_Secure_9f83xA72"


# ============================================================
# SERVER ROOM SECOND FACTOR
# ============================================================

# This PIN is entered by the security operator
# in the dashboard after a valid Server Room card scan.

SERVER_ROOM_PIN = "2468"