from flask import Flask, request, jsonify, send_file
import sqlite3
import hashlib
import os

app = Flask(__name__)
DATABASE = 'users.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable accessing columns by name.
    return conn

def get_user_id_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    conn.close()
    
    if user:
        return user['id']
    return None

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Create the user table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    ''')

    # Create the files table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            data BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
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

def save_file_to_db(user_id, filename, data):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO files (user_id, filename, data) VALUES (?, ?, ?)', (user_id, filename, data))
        conn.commit()
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

def get_file_from_db(user_id, filename):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT data FROM files WHERE user_id = ? AND filename = ?', (user_id, filename))
    file = cur.fetchone()
    conn.close()
    
    if file:
        return file['data']
    return None

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if a file part is present in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    # Check if a filename is provided
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    username = request.form.get('username')  # Get the username from form data
    
    if username is None:
        return jsonify({'error': 'Username is required'}), 400  # Check if username is provided

    user_id = get_user_id_by_username(username) # Get the user_id based on the username
    
    if user_id is None:
        return jsonify({'error': 'User not found'}), 404  # Return error if user is not found
    
    file_data = file.read()  # Read the file data
    
    response = save_file_to_db(user_id, file.filename, file_data)
    if response is not None: # If an error occurred while saving the file to the database
        return response
    
    return jsonify({'message': 'File uploaded successfully'}), 201

temp_files = set() # Set to track temporary files

@app.after_request
def remove_temp_files(response):
    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)
    temp_files.clear()
    return response

@app.route('/download', methods=['GET'])
def download_file():
    username = request.args.get('username') # Get the username from the query parameters
    filename = request.args.get('filename') # Get the filename from the query parameters

    user_id = get_user_id_by_username(username) # Get the user_id based on the username
    if user_id is None:
        return jsonify({'error': 'User not found'}), 404  # Return error if user is not found
    
    if filename is None:
        return jsonify({'error': 'Filename is required'}), 400 # Return error if filename is not provided
    
    file_data = get_file_from_db(user_id, filename)  # Get the file data from the database
    if file_data is None:
        return jsonify({'error': 'File not found'}), 404 # Return error if file is not found
    
    temp_file_path = f'temp_{filename}' # Create a temporary file path
    with open(temp_file_path, 'wb') as f:
        f.write(file_data)  # Write the file data to a temporary file
    
    temp_files.add(temp_file_path)  # Add the temp file to the tracking set
    
    return send_file(temp_file_path, as_attachment=True)  # Send the file as an attachment
    


if __name__ == '__main__':
    init_db()  # Create the database and table if they don't exist.
    app.run(debug=True)
