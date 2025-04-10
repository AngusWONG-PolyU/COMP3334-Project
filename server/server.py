from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, make_response
import sqlite3
import hashlib
import os
import hmac
import time
from functools import wraps
import base64
import datetime
import pyotp

app = Flask(__name__)
DATABASE = 'database.db'
SERVER_SECRET = os.urandom(32)  # used for signing session cookies
# A server secret used to sign the logs. Keep this secure.
LOG_SECRET = b'super_secret_log_key'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # enable dictionary-like access to columns
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create the users table.
    # Note: public_key is allowed to be NULL.
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT,
            otp_secret TEXT NOT NULL,  -- store the OTP key
            failed_attempts INTEGER DEFAULT 0,
            lockout_time DATETIME
        );
    ''')

    # Create the files table.
    cur.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            enc_aes_key TEXT NOT NULL,
            file_data BLOB NOT NULL,
            shared_by TEXT DEFAULT NULL
        );
    ''')

    # Create the logs table.
    cur.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            operation TEXT,
            details TEXT,
            log_hash TEXT
        );
    ''')

    # Insert admin user if not exists.
    cur.execute("SELECT * FROM users WHERE username = 'admin'")
    if cur.fetchone() is None:
        admin_username = "admin"
        # For demonstration only—use a strong password in production.
        admin_password = "admin"
        hashed_admin_password = hash_password(admin_password)
        # Insert admin user with public_key set to NULL.
        cur.execute("INSERT INTO users (username, password, public_key,otp_secret) VALUES (?, ?, ?,?)",
                    (admin_username, hashed_admin_password, None, admin_password))

    conn.commit()
    conn.close()


def get_last_log_hash():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT log_hash FROM logs ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row["log_hash"] if row else ""


def log_operation(username, operation, details):
    """
    Records a log entry in the logs table.
    Computes a hash for non-repudiation that chains with the previous log hash.
    """
    last_hash = get_last_log_hash()
    # Prepare a string that includes the operation details, timestamp, username, etc.
    # (Note: In a real application, you might include the timestamp, but here we assume the DB timestamp.)
    log_string = f"{username}|{operation}|{details}|{last_hash}|{LOG_SECRET.decode()}"
    # Compute SHA-256 hash.
    log_hash = hashlib.sha256(log_string.encode()).hexdigest()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (username, operation, details, log_hash)
        VALUES (?, ?, ?, ?)
    """, (username, operation, details, log_hash))
    conn.commit()
    conn.close()


@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'User not found'}), 404

    public_key = row['public_key']
    return jsonify({'public_key': public_key})


def hash_password(password):
    """
    Hash a password using PBKDF2_HMAC with a random salt.
    Returns a string in the format: "salt$hash".
    """
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + '$' + hashed.hex()


def verify_password(stored_password, provided_password):
    """
    Verify a provided password against the stored hash.
    """
    try:
        salt_hex, hash_hex = stored_password.split('$')
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    new_hash = hashlib.pbkdf2_hmac(
        'sha256', provided_password.encode(), salt, 100000)
    return new_hash.hex() == hash_hex


def generate_session_cookie(username):
    """
    Generates a session cookie containing the username and an expiration timestamp,
    and appends an HMAC signature.
    """
    expiration = int(time.time()) + 3600  # valid for 1 hour
    session_data = f"{username}:{expiration}"
    signature = hmac.new(SERVER_SECRET, session_data.encode(),
                         hashlib.sha256).hexdigest()
    cookie = f"{session_data}:{signature}"
    return cookie


def verify_session_cookie(cookie):
    """
    Verifies that the session cookie is intact and not expired.
    Returns the username if valid, or None otherwise.
    """
    try:
        parts = cookie.split(':')
        if len(parts) != 3:
            return None
        username, expiration, signature = parts
        session_data = f"{username}:{expiration}"
        expected_signature = hmac.new(
            SERVER_SECRET, session_data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            return None
        if int(expiration) < time.time():
            return None
        return username
    except Exception:
        return None


def require_login(f):
    """
    A decorator that checks for a valid session cookie.
    Attaches the username (from the cookie) to the request object.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cookie = request.cookies.get('session')
        if not cookie:
            return jsonify({'error': 'Authentication required'}), 401
        username = verify_session_cookie(cookie)
        if not username:
            return jsonify({'error': 'Invalid or expired session'}), 401
        request.username = username
        return f(*args, **kwargs)
    return decorated_function


@app.route('/check_username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Missing username parameter'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    exists = cur.fetchone() is not None
    conn.close()

    return jsonify({'exists': exists})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')  # New field: user's RSA public key
    otp_secret = data.get('otp_secret')  # OTP secret provided by the user

    if not username or not password or not public_key or not otp_secret:
        return jsonify({'error': 'Username, password, public key, and OTP secret are required'}), 400

    if not username.isalnum():
        return jsonify({'error': 'Username can only contain letters and numbers.'}), 400

    # TODO: Change back to 10
    if len(password) < 1:
        return jsonify({'error': 'Password must be at least 10 characters long'}), 400

    try:
        # The function will raise an exception if s is not valid base32.
        base64.b32decode(otp_secret, casefold=True)
    except Exception:
        return jsonify({'error': 'Invalid OTP secret. It must be a valid base32 encoded string.'}), 400

    hashed_password = hash_password(password)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password, public_key, otp_secret) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, public_key, otp_secret))
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
    otp_input = data.get('otp')  # one-time password from the client
    if not username or not password or not otp_input:
        return jsonify({'error': 'Username, password, and OTP required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401

    # Check if account is currently locked.
    lockout_time = user['lockout_time']
    if lockout_time:
        # SQLite returns DATETIME as a string, e.g. "2023-03-15 12:34:56"
        current_time = datetime.datetime.now()
        lockout_time_dt = datetime.datetime.strptime(
            lockout_time, "%Y-%m-%d %H:%M:%S")
        if current_time < lockout_time_dt:
            remaining = (lockout_time_dt - current_time).seconds
            conn.close()
            return jsonify({'error': f"Account locked. Try again after {remaining} seconds."}), 403

    # Verify the OTP using the stored OTP secret.
    otp_secret = user['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    # Check password and OTP.
    # Allow an extra window of 1 step (30 seconds) so that the OTP from the previous tick is also accepted.
    if not verify_password(user['password'], password) or not totp.verify(otp_input, valid_window=1):
        log_operation(username, "login fail",
                      f"User {username} logged in fail. From {request.remote_addr}")
        failed_attempts = user['failed_attempts'] if user['failed_attempts'] is not None else 0
        failed_attempts += 1
        # If maximum attempts reached, lock account for 5 minutes. (30 seconds for demo)
        if failed_attempts >= 3:
            # lockout_period = datetime.timedelta(minutes=5)
            lockout_period = datetime.timedelta(seconds=30)
            new_lockout_time = datetime.datetime.now() + lockout_period
            new_lockout_time_str = new_lockout_time.strftime(
                "%Y-%m-%d %H:%M:%S")
            cur.execute("UPDATE users SET failed_attempts = 0, lockout_time = ? WHERE username = ?",
                        (new_lockout_time_str, username))
            conn.commit()
            conn.close()
            return jsonify({'error': "Too many failed login attempts. Account locked for 30 seconds."}), 403
        else:
            cur.execute("UPDATE users SET failed_attempts = ? WHERE username = ?",
                        (failed_attempts, username))
            conn.commit()
            conn.close()
            return jsonify({'error': "Invalid username or password or OTP."}), 401

    # Successful login: reset failed_attempts and lockout_time.
    cur.execute("UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE username = ?",
                (username,))
    conn.commit()
    conn.close()

    cookie = generate_session_cookie(username)
    response = make_response(jsonify({'message': 'Logged in successfully'}))
    response.set_cookie('session', cookie, httponly=True, samesite='Strict')

    log_operation(username, "login",
                  f"User {username} logged in. From {request.remote_addr}")
    return response


@app.route('/reset_password', methods=['POST'])
@require_login
def reset_password():
    data = request.get_json()
    username = request.username
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not username or not old_password or not new_password:
        return jsonify({'error': 'Username, old password, and new password are required'}), 400

    # TODO: Change back to 10
    if len(new_password) < 1:
        return jsonify({'error': 'Password must be at least 10 characters long'}), 400

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


@app.route('/logout', methods=['POST'])
@require_login
def logout():
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.set_cookie('session', '', expires=0)
    log_operation(request.username, "logout",
                  f"User {request.username} logged out.")
    return response


@app.route('/upload_file', methods=['POST'])
@require_login
def upload_file():
    username = request.username
    # Get the raw filename, encrypted AES key, and file upload.
    raw_filename = request.form.get('filename')
    enc_aes_key = request.form.get('enc_aes_key')
    uploaded_file = request.files.get('file')

    if not raw_filename or not enc_aes_key or not uploaded_file:
        return jsonify({'error': 'Missing parameters'}), 400

    # Sanitize the filename.
    filename = secure_filename(raw_filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    # Read the file's binary content.
    file_data = uploaded_file.read()

    # Store the file metadata and binary data in the database.
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO files (owner, filename, enc_aes_key, file_data) VALUES (?, ?, ?, ?)',
                (username, filename, enc_aes_key, file_data))
    conn.commit()
    conn.close()
    log_operation(username, "upload", f"Uploaded file '{filename}'.")
    return jsonify({'message': 'File uploaded successfully'})


@app.route('/list_files', methods=['GET'])
@require_login
def list_files():
    conn = get_db_connection()
    cur = conn.cursor()
    # Retrieve all files where the logged-in user is the owner.
    cur.execute(
        'SELECT id, filename, shared_by FROM files WHERE owner = ?', (request.username,))
    files = cur.fetchall()
    conn.close()

    file_list = []
    for f in files:
        file_dict = {
            "id": f["id"],
            "filename": f["filename"]
        }
        # Only include the "shared_by" field if it is not empty or NULL.
        if f["shared_by"]:
            file_dict["shared_by"] = f["shared_by"]
        file_list.append(file_dict)

    return jsonify({"files": file_list})


@app.route('/download_file', methods=['POST'])
@require_login
def download_file():
    data = request.get_json()
    file_id = data.get('file_id')
    if not file_id:
        return jsonify({'error': 'Missing file_id'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM files WHERE id = ? AND owner = ?',
                (file_id, request.username))
    file_record = cur.fetchone()
    conn.close()

    if not file_record:
        return jsonify({'error': 'File not found'}), 404

    # Encode the binary file data for transport.
    file_content_b64 = base64.b64encode(
        file_record['file_data']).decode('utf-8')
    return jsonify({
        'filename': file_record['filename'],
        'enc_aes_key': file_record['enc_aes_key'],
        'file_content': file_content_b64
    })


@app.route('/edit_file', methods=['POST'])
@require_login
def edit_file():
    username = request.username
    file_id = request.form.get('file_id')
    if not file_id:
        return jsonify({'error': 'Missing file_id'}), 400

    # Read new update values from the form.
    # These fields are optional: user can update filename, encrypted AES key, and/or file content.
    new_raw_filename = request.form.get('filename')
    new_enc_aes_key = request.form.get('enc_aes_key')
    new_file = request.files.get('file')

    # At least one update must be provided.
    if not new_raw_filename and not new_enc_aes_key and not new_file:
        return jsonify({'error': 'No update provided'}), 400

    # Sanitize the new filename if provided.
    new_filename = None
    if new_raw_filename:
        new_filename = secure_filename(new_raw_filename)
        if not new_filename:
            return jsonify({'error': 'Invalid filename'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    # Ensure that the file exists and belongs to the logged-in user.
    cur.execute('SELECT * FROM files WHERE id = ? AND owner = ?',
                (file_id, username))
    file_record = cur.fetchone()
    if not file_record:
        conn.close()
        return jsonify({'error': 'File not found or access denied'}), 404

    # Build the update query dynamically based on provided fields.
    update_fields = []
    params = []

    if new_filename:
        update_fields.append('filename = ?')
        params.append(new_filename)
    if new_enc_aes_key:
        update_fields.append('enc_aes_key = ?')
        params.append(new_enc_aes_key)
    if new_file:
        # Read and update the file data.
        file_data = new_file.read()
        update_fields.append('file_data = ?')
        params.append(file_data)

    # If no update fields are provided (this check is redundant due to the earlier check but kept for safety)
    if not update_fields:
        conn.close()
        return jsonify({'error': 'No update fields provided'}), 400

    # Append file_id and owner for the WHERE clause.
    params.append(file_id)
    params.append(username)
    query = f"UPDATE files SET {', '.join(update_fields)} WHERE id = ? AND owner = ?"
    cur.execute(query, params)
    conn.commit()
    conn.close()

    return jsonify({'message': 'File updated successfully'})


@app.route('/share_file', methods=['POST'])
@require_login
def share_file():
    """
    Allows a user to share one of their files with a designated user.
    Expects form fields:
      - original_file_id: The ID of the file being shared.
      - target_username: The recipient's username.
      - filename: The file name.
      - enc_aes_key: The new encrypted AES key (base64 encoded) for the recipient.
    Expects the re-encrypted file data in the file upload field "file".
    """
    data = request.form
    original_file_id = data.get('original_file_id')
    target_username = data.get('target_username')
    filename = data.get('filename')
    enc_aes_key = data.get('enc_aes_key')
    shared_file = request.files.get('file')

    if not original_file_id or not target_username or not filename or not enc_aes_key or not shared_file:
        return jsonify({'error': 'Missing parameters'}), 400

    # Verify the current user is the owner of the original file.
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM files WHERE id = ? AND owner = ?',
                (original_file_id, request.username))
    original_file = cur.fetchone()
    if not original_file:
        conn.close()
        return jsonify({'error': 'File not found or access denied'}), 404

    # Read the re-encrypted file data.
    new_file_data = shared_file.read()
    # Insert a new record for the shared file.
    cur.execute('INSERT INTO files (owner, filename, enc_aes_key, file_data, shared_by) VALUES (?, ?, ?, ?, ?)',
                (target_username, filename, enc_aes_key, new_file_data, request.username))
    conn.commit()
    conn.close()
    log_operation(request.username, "share",
                  f"Shared file id {original_file_id} with {target_username}.")
    return jsonify({'message': f'File shared successfully with {target_username}'})


@app.route('/delete_file', methods=['POST'])
@require_login
def delete_file():
    data = request.get_json()
    file_id = data.get("file_id")
    if not file_id:
        return jsonify({'error': 'Missing file_id parameter'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    # Check if the file exists and belongs to the current user.
    cur.execute("SELECT * FROM files WHERE id = ? AND owner = ?",
                (file_id, request.username))
    file_record = cur.fetchone()
    if not file_record:
        conn.close()
        return jsonify({'error': 'File not found or access denied'}), 404

    # Delete the file record.
    cur.execute("DELETE FROM files WHERE id = ? AND owner = ?",
                (file_id, request.username))
    conn.commit()
    conn.close()
    log_operation(request.username, "delete",
                  f"Deleted file with id {file_id}.")
    return jsonify({'message': 'File deleted successfully'})


@app.route('/get_logs', methods=['GET'])
@require_login
def get_logs():
    # For simplicity, assume the admin has username "admin".
    if request.username != "admin":
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cur.fetchall()
    conn.close()

    # Convert log rows to a list of dictionaries.
    log_list = []
    for row in logs:
        log_list.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "username": row["username"],
            "operation": row["operation"],
            "details": row["details"],
            "log_hash": row["log_hash"]
        })
    return jsonify({"logs": log_list})


if __name__ == '__main__':
    init_db()  # initialize the database and tables if they don't exist
    app.run(host="127.0.0.1", ssl_context=("cert.pem", "key.pem"), debug=True)
