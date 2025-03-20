from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os

app = Flask(__name__)
DATABASE = 'users.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable accessing columns by name.
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


def hash_password(password):
    """
    Hash the provided password using PBKDF2_HMAC with a random salt.
    Returns a string in the format "salt$hash", where both parts are hex encoded.
    """
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + '$' + hashed.hex()


def verify_password(stored_password, provided_password):
    """
    Verify a provided password against the stored hash.
    The stored password is expected in the format "salt$hash".
    """
    try:
        salt_hex, hash_hex = stored_password.split('$')
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    new_hash = hashlib.pbkdf2_hmac(
        'sha256', provided_password.encode(), salt, 100000)
    return new_hash.hex() == hash_hex


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    hashed_password = hash_password(password)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                    (username, hashed_password))
        conn.commit()
        return jsonify({'message': 'User registered successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()

    if user is None:
        return jsonify({'error': 'Invalid username or password'}), 401

    stored_password = user['password']
    if verify_password(stored_password, password):
        return jsonify({'message': 'Logged in successfully'})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not username or not old_password or not new_password:
        return jsonify({'error': 'Username, old password, and new password are required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cur.fetchone()

    if user is None:
        conn.close()
        return jsonify({'error': 'User does not exist'}), 404

    stored_password = user['password']
    if not verify_password(stored_password, old_password):
        conn.close()
        return jsonify({'error': 'Old password is incorrect'}), 401

    new_hashed_password = hash_password(new_password)
    cur.execute('UPDATE users SET password = ? WHERE username = ?',
                (new_hashed_password, username))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Password reset successfully'})


if __name__ == '__main__':
    init_db()  # Create the database and table if they don't exist.
    app.run(debug=True)
