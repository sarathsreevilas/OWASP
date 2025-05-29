from flask import Flask, request, render_template
import sqlite3
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ✅ Define app before using any @app.route
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        query = "SELECT password FROM users WHERE username = ?"
        c.execute(query, (username,))
        row = c.fetchone()
        conn.close()

        if row and bcrypt.checkpw(password.encode(), row[0]):
            return "✅ Logged in successfully"
        else:
            return "❌ Invalid credentials"
    
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
