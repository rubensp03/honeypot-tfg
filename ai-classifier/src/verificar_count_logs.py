import sqlite3

from config import DB_HONEYPOT_DEEPSEEK

conn = sqlite3.connect(str(DB_HONEYPOT_DEEPSEEK))
cursor = conn.cursor()
cursor.execute('SELECT count(*) FROM alertas_ia')
print('Total DB rows:', cursor.fetchone()[0])
conn.close()
