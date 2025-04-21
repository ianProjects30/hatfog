from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import hashlib
import os
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key'

DB_FILE = 'users.db'
SECRET_PEPPER = 'my secret pepper'

# Load ML model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

# ---------------- DATABASE INIT ---------------- #
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL,
            salt_for_secret BLOB NOT NULL,
            hashed_secret2 BLOB NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            confidence REAL NOT NULL,
            is_safe INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------------- AUTH LOGIC ---------------- #
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
        cursor.execute('INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2) VALUES (?, ?, ?, ?)',
                       (email, final_hashed_password, salt_for_secret, hashed_secret2))
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

# ---------------- ROUTES ---------------- #
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('auth'))

    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            # Save to history
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO url_history (username, url, confidence, is_safe) VALUES (?, ?, ?, ?)',
                           (session['user'], url, y_pro_non_phishing, int(y_pred)))
            conn.commit()
            conn.close()

            return render_template('index.html', user=session['user'], xx=round(y_pro_non_phishing, 2), url=url)

    return render_template('index.html', user=session['user'], xx=-1)

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('auth'))

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT url, confidence, is_safe, timestamp FROM url_history WHERE username = ? ORDER BY timestamp DESC', (session['user'],))
    rows = cursor.fetchall()
    conn.close()

    cleaned_rows = []
    for row in rows:
        url = row[0]
        raw_conf = row[1]

        # Attempt to handle possible bytes type without decoding to string
        try:
            if isinstance(raw_conf, bytes):
                confidence = float.fromhex(raw_conf.hex())  # Try interpreting it as raw float bytes
            else:
                confidence = float(raw_conf)
        except Exception:
            confidence = 0.0  # fallback if parsing fails

        is_safe = row[2]
        timestamp = row[3]
        cleaned_rows.append((url, confidence, is_safe, timestamp))

    return render_template('history.html', user=session['user'], history=cleaned_rows)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        mode = request.form['form_mode']
        email = request.form['email']
        password = request.form['password']

        if mode == 'signup':
            confirm = request.form.get('confirmPassword')
            if password != confirm:
                flash("Passwords do not match.", "danger")
            elif create_user(email, password):
                flash("Account created! Please log in.", "success")
            else:
                flash("Email already exists.", "danger")
        else:
            if validate_login(email, password):
                session['user'] = email
                flash(f"Welcome back, {email}!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('auth'))

if __name__ == '__main__':
    app.run(debug=True)