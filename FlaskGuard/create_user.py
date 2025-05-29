import sqlite3
import bcrypt

username = 'admin'
password = 'admin123'

# Hash the password
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Connect and reset the database
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute("DROP TABLE IF EXISTS users")
c.execute("CREATE TABLE users (username TEXT, password TEXT)")
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))

conn.commit()
conn.close()

print("✅ User created with hashed password.")
