from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import sqlite3
import hashlib
import os

app = Flask(__name__)
DATABASE = 'users.db'

# Database helpers


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Allow accessing columns by name
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

# Password hashing using PBKDF2


def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + '$' + hashed.hex()


def verify_password(stored_password, provided_password):
    try:
        salt_hex, hash_hex = stored_password.split('$')
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    new_hash = hashlib.pbkdf2_hmac(
        'sha256', provided_password.encode(), salt, 100000)
    return new_hash.hex() == hash_hex

# Home page with links to functionalities


@app.route('/')
def index():
    return render_template_string('''
    <!doctype html>
    <html>
      <head>
        <title>Online Storage Application</title>
      </head>
      <body>
        <h1>Welcome to the Online Storage Application</h1>
        <ul>
          <li><a href="{{ url_for('register') }}">Register</a></li>
          <li><a href="{{ url_for('login') }}">Login</a></li>
          <li><a href="{{ url_for('reset_password') }}">Reset Password</a></li>
        </ul>
      </body>
    </html>
    ''')

# Registration: HTML form on GET, process data on POST.


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string('''
        <!doctype html>
        <html>
          <head>
            <title>Register</title>
          </head>
          <body>
            <h2>Register</h2>
            <form method="post" action="{{ url_for('register') }}">
              <label>Username:</label>
              <input type="text" name="username" required /><br/>
              <label>Password:</label>
              <input type="password" name="password" required /><br/>
              <input type="submit" value="Register" />
            </form>
            <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
          </body>
        </html>
        ''')
    else:
        # Support both JSON and form-data submissions
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            return render_template_string('<p>Error: Username and password are required.</p>'), 400

        hashed_password = hash_password(password)
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hashed_password))
            conn.commit()
            conn.close()
            return render_template_string('''
            <!doctype html>
            <html>
              <head><title>Registration Successful</title></head>
              <body>
                <p>User registered successfully!</p>
                <p><a href="{{ url_for('login') }}">Click here to login</a></p>
              </body>
            </html>
            ''')
        except sqlite3.IntegrityError:
            return render_template_string('<p>Error: Username already exists.</p>'), 400

# Login: Display HTML form on GET, process login on POST.


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string('''
        <!doctype html>
        <html>
          <head>
            <title>Login</title>
          </head>
          <body>
            <h2>Login</h2>
            <form method="post" action="{{ url_for('login') }}">
              <label>Username:</label>
              <input type="text" name="username" required /><br/>
              <label>Password:</label>
              <input type="password" name="password" required /><br/>
              <input type="submit" value="Login" />
            </form>
            <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
            <p>Forgot your password? <a href="{{ url_for('reset_password') }}">Reset Password</a></p>
          </body>
        </html>
        ''')
    else:
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            return render_template_string('<p>Error: Username and password are required.</p>'), 400

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()

        if user is None or not verify_password(user['password'], password):
            return render_template_string('<p>Error: Invalid username or password.</p>'), 401

        return render_template_string('''
        <!doctype html>
        <html>
          <head>
            <title>Login Successful</title>
          </head>
          <body>
            <p>Logged in successfully!</p>
            <p>Welcome, {{ username }}!</p>
            <p><a href="{{ url_for('index') }}">Home</a></p>
          </body>
        </html>
        ''', username=username)

# Password Reset: Show reset form on GET, update password on POST.


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        return render_template_string('''
        <!doctype html>
        <html>
          <head>
            <title>Reset Password</title>
          </head>
          <body>
            <h2>Reset Password</h2>
            <form method="post" action="{{ url_for('reset_password') }}">
              <label>Username:</label>
              <input type="text" name="username" required /><br/>
              <label>Old Password:</label>
              <input type="password" name="old_password" required /><br/>
              <label>New Password:</label>
              <input type="password" name="new_password" required /><br/>
              <input type="submit" value="Reset Password" />
            </form>
            <p><a href="{{ url_for('login') }}">Back to Login</a></p>
          </body>
        </html>
        ''')
    else:
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            old_password = data.get('old_password')
            new_password = data.get('new_password')
        else:
            username = request.form.get('username')
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')

        if not username or not old_password or not new_password:
            return render_template_string('<p>Error: All fields are required.</p>'), 400

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()

        if user is None:
            conn.close()
            return render_template_string('<p>Error: User does not exist.</p>'), 404

        if not verify_password(user['password'], old_password):
            conn.close()
            return render_template_string('<p>Error: Old password is incorrect.</p>'), 401

        new_hashed_password = hash_password(new_password)
        cur.execute('UPDATE users SET password = ? WHERE username = ?',
                    (new_hashed_password, username))
        conn.commit()
        conn.close()

        return render_template_string('''
        <!doctype html>
        <html>
          <head>
            <title>Password Reset Successful</title>
          </head>
          <body>
            <p>Password reset successfully!</p>
            <p><a href="{{ url_for('login') }}">Click here to login</a></p>
          </body>
        </html>
        ''')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
