# Angus
import sqlite3

conn = sqlite3.connect('database.db')

print("Open database successfully")

conn.close()