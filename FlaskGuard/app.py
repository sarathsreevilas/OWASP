from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps

# ----------------------------------------
# ✅ Initialize Flask App and Config
# ----------------------------------------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # 🔐 Needed for sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # local SQLite DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ----------------------------------------
# ✅ Initialize DB and Bcrypt
# ----------------------------------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ----------------------------------------
# ✅ User Model (Database Table)
# ----------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID
    username = db.Column(db.String(100), unique=True, nullable=False)  # Unique username
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    role = db.Column(db.String(20), default='user')  # 🆕 'admin' or 'user'

# ----------------------------------------
# ✅ Decorator for Admin-Only Routes
# ----------------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Login required.', 'error')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Access denied: Admins only.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------
# ✅ Routes
# ----------------------------------------

@app.route('/')
def home():
    return redirect(url_for('login'))

# 🔐 Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_pw = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(raw_pw).decode('utf-8')

        # First user = admin, rest = user
        role = 'admin' if User.query.count() == 0 else 'user'

        new_user = User(username=username, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# 🔐 Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('login.html')



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 🔧 Creates users.db and User table if not exists
    app.run(debug=True)  # 🔥 Starts Flask app at http://127.0.0.1:5000/
