import sqlite3
conn = sqlite3.connect('honeypot.db')
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM attack_logs")
print("attack_logs BEFORE:", cur.fetchone()[0])
cur.execute("SELECT COUNT(*) FROM attacker_sessions")
print("attacker_sessions BEFORE:", cur.fetchone()[0])
conn.close()
