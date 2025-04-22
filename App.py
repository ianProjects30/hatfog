from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.google import make_google_blueprint
import sqlite3
import bcrypt
import hashlib
import os
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction
import os


warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key'

# --- OAuth setup ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

google_bp = make_google_blueprint(
    client_id="",
    client_secret="",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_url="/google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# --- Constants ---
DB_FILE = 'users.db'
SECRET_PEPPER = 'my secret pepper'

# --- Load ML model ---
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Users table
    cursor.execute('''
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        hashed_password BLOB NOT NULL,
        salt_for_secret BLOB NOT NULL,
        hashed_secret2 BLOB NOT NULL
      )
    ''')
    # History table
    cursor.execute('''
      CREATE TABLE IF NOT EXISTS url_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        url TEXT NOT NULL,
        confidence REAL NOT NULL,
        is_safe INTEGER NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(username) REFERENCES users(username)
        ON DELETE CASCADE
      )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions for Auth ---
def generate_random_salt():
    return os.urandom(16)

def hash_secret_with_salt(secret, salt):
    return hashlib.sha256(secret.encode('utf-8') + salt).hexdigest()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    salt_for_secret = generate_random_salt()
    hashed_secret = hash_secret_with_salt(SECRET_PEPPER, salt_for_secret)
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())
    combined_password = password + hashed_secret2.decode('utf-8')
    final_hashed_password = bcrypt.hashpw(combined_password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2) VALUES (?, ?, ?, ?)',
            (email, final_hashed_password, salt_for_secret, hashed_secret2)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return False
    stored_hashed_password, salt, hashed_secret2 = user[1], user[2], user[3]
    combined_input = password + hashed_secret2.decode('utf-8')
    return bcrypt.checkpw(combined_input.encode('utf-8'), stored_hashed_password)

# --- Routes ---

# Home / Phishing Check
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('auth'))

    xx = -1
    url = None

    if request.method == 'POST':
        url = request.form.get('url').strip()
        if url:
            # feature extraction + prediction
            obj = FeatureExtraction(url)
            features = obj.getFeaturesList()
            X = np.array(features).reshape(1, -1)
            y_pred = gbc.predict(X)[0]
            pro_safe = gbc.predict_proba(X)[0, 1]

            # save history
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO url_history (username, url, confidence, is_safe) VALUES (?, ?, ?, ?)',
                (session['user'], url, float(pro_safe), int(y_pred))
            )
            conn.commit()
            conn.close()

            xx = round(pro_safe, 2)

    return render_template('index.html', user=session['user'], xx=xx, url=url)

# View History
@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('auth'))

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT url, confidence, is_safe, timestamp '
        'FROM url_history WHERE username = ? '
        'ORDER BY timestamp DESC',
        (session['user'],)
    )
    rows = cursor.fetchall()
    conn.close()
    return render_template('history.html', user=session['user'], history=rows)

# Combined Login / Signup Page
@app.route('/auth', methods=['GET', 'POST'])
def auth():
    # If already logged in, redirect home
    if 'user' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        mode = request.form['form_mode']
        email = request.form['email'].strip().lower()
        password = request.form['password']

        if mode == 'signup':
            confirm = request.form.get('confirmPassword')
            if password != confirm:
                flash("Passwords do not match.", "danger")
            elif create_user(email, password):
                flash("Account created! Please log in.", "success")
            else:
                flash("Email already exists.", "warning")
        else:  # login
            if validate_login(email, password):
                session['user'] = email
                flash(f"Welcome back, {email}!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "danger")

    return render_template('login.html')

# Google OAuth Callback / Login
@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for('auth'))

    user_info = resp.json()
    email = user_info.get("email").lower()

    # Auto‑create user if not exists
    if not get_user_by_email(email):
        dummy_pass = bcrypt.gensalt().decode('utf-8')
        create_user(email, dummy_pass)

    # Log in
    session['user'] = email
    flash(f"Logged in as {email} via Google.", "success")
    return redirect(url_for('home'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('auth'))

# Run
if __name__ == '__main__':
    app.run(debug=True)
