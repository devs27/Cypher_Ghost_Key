import sqlite3
conn = sqlite3.connect('backend/ghostkey.db')
conn.row_factory = sqlite3.Row
row = conn.execute('SELECT * FROM cards WHERE uid=?', ('E2E93719',)).fetchone()
if row:
    print(dict(row))
else:
    print("NOT FOUND")
conn.close()
