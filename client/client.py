import os
import base64
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass

SERVER_URL = 'https://127.0.0.1:5000'
# Global variables to cache the RSA key encryption password and username during the session.
KEY_PASSWORD = None
SESSION_USERNAME = None


def is_valid_base32(s):
    """
    Checks if the string s is a valid base32 encoded value.
    The function attempts to decode s using base64.b32decode (case-insensitive).
    """
    try:
        # The function will raise an exception if s is not valid base32.
        base64.b32decode(s, casefold=True)
        return True
    except Exception:
        return False


def generate_rsa_keys(username, key_password):
    """
    Generate an RSA key pair for the given username.
    The private key is encrypted using the provided key_password.
    If the key files already exist, no new keys are generated.
    """
    private_key_filename = f"{username}_private.pem"
    public_key_filename = f"{username}_public.pem"

    if os.path.exists(private_key_filename) and os.path.exists(public_key_filename):
        print("RSA key pair already exists.")
        return

    # Generate RSA key pair.
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)

    # Serialize and encrypt the private key using the key_password.
    with open(private_key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_password.encode())
        ))

    # Serialize the public key (no encryption needed).
    public_key = private_key.public_key()
    with open(public_key_filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("RSA key pair generated and saved (private key is encrypted).")


def load_rsa_private_key():
    """
    Load the RSA private key using the global SESSION_USERNAME.
    Uses the cached KEY_PASSWORD from the session to decrypt the private key.
    If KEY_PASSWORD is not set, prompts the user for it.
    """
    global KEY_PASSWORD
    if not SESSION_USERNAME:
        print("No user logged in.")
        return None
    private_key_filename = f"{SESSION_USERNAME}_private.pem"
    if not os.path.exists(private_key_filename):
        print("RSA private key not found. Please register first.")
        return None
    if KEY_PASSWORD is None:
        key_pass = getpass.getpass(
            "Enter the separate password for decrypting your RSA private key: ").strip()
    else:
        key_pass = KEY_PASSWORD
    try:
        with open(private_key_filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=key_pass.encode()
            )
        KEY_PASSWORD = key_pass
        return private_key
    except Exception as e:
        print("Failed to load private key:", e)
        return None


def get_public_key_from_server(session, target_username=None):
    """
    Retrieve the RSA public key for the specified target_username from the server.
    If target_username is not provided, use the global SESSION_USERNAME.
    The server must expose an endpoint (e.g. GET /get_public_key?username=...)
    that returns a JSON response containing the public key in PEM format under the "public_key" field.
    """
    if target_username is None:
        target_username = SESSION_USERNAME
    try:
        response = session.get(
            f"{SERVER_URL}/get_public_key?username={target_username}", verify="cert.pem")
        if response.status_code != 200:
            print("Error getting public key from server:",
                  response.json().get("error"))
            return None
        public_key_pem = response.json().get("public_key")
        if not public_key_pem:
            print("Public key not found in server response.")
            return None
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        return public_key
    except Exception as e:
        print("Error fetching public key from server:", e)
        return None


def print_menu_logged_out():
    print("\n=== Online Storage Application ===")
    print("1. Register")
    print("2. Login")
    print("3. Quit")


def print_menu_admin():
    print(f"\n=== Welcome, {SESSION_USERNAME}! ===")
    print("1. View Logs")
    print("2. Logout")


def print_menu_logged_in():
    print(f"\n=== Welcome, {SESSION_USERNAME}! ===")
    print("1. Upload File")
    print("2. List Files")
    print("3. Download File")
    print("4. Edit File")
    print("5. Share File")
    print("6. Unshare File")
    print("7. Send File")
    print("8. Delete File")
    print("9. Reset Password")
    print("10. Logout")


def validate_password(password):
    """
    Validate password requirements.
    Returns (bool, str) tuple: (is_valid, error_message)
    """
    # TODO: Change back to 10
    if len(password) < 1:
        return False, "Password must be at least 10 characters long"
    return True, ""


def is_valid_username(username):
    for char in username:
        if not (char.isalnum() or char == '_'):
            return False
    return True


def register():
    print("\n--- Register ---")
    while True:
        username = input(
            'Enter username (only letters, numbers, and underscores) (Type "exit" to exit): ').strip()
        if is_valid_username(username) or username == "exit":
            if username == "exit":
                return
            break
        print("Invalid username. Please try again.")
    # Check if username already exists
    try:
        response = requests.get(
            f"{SERVER_URL}/check_username?username={username}", verify="cert.pem")
        if response.status_code == 200:
            data = response.json()
            if data.get("exists", False):
                print("Username already exists. Please choose a different username.")
                return
        else:
            print("Error checking username uniqueness. Please try again later.")
            return
    except Exception as e:
        print("Error checking username uniqueness:", e)
        return

    # Get and validate login password
    while True:
        login_pass = getpass.getpass(
            "Enter login password (min 10 characters): ").strip()
        is_valid, error_msg = validate_password(login_pass)
        if not is_valid:
            print(f"Invalid password: {error_msg}")
            continue
        break

    # Get and validate key password
    while True:
        key_pass = getpass.getpass(
            "Enter a separate password for encrypting your RSA private key (min 10 characters): ").strip()
        is_valid, error_msg = validate_password(key_pass)
        if not is_valid:
            print(f"Invalid key password: {error_msg}")
            continue

        # Check if key password is different from login password
        if key_pass == login_pass:
            print("Error: Key password must be different from login password")
            continue
        break

    # Get and validate otp seceret
    while True:
        otp_secret = getpass.getpass(
            "Enter your OTP secret (in base32): ").strip()
        if not is_valid_base32(otp_secret):
            print("Invalid OTP secret. It must be a valid base32 encoded string.")
            continue
        break

    # Generate RSA key pair using the separate key password.
    generate_rsa_keys(username, key_pass)
    # Load the public key from local file.
    public_key_filename = f"{username}_public.pem"
    with open(public_key_filename, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    # Serialize the public key to a PEM-formatted string.
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    data = {"username": username, "password": login_pass,
            "public_key": public_key_pem, "otp_secret": otp_secret}
    try:
        response = requests.post(
            f"{SERVER_URL}/register", json=data, verify="cert.pem")
        resp = response.json()
        print(resp.get("message") or resp.get("error"))
    except Exception as e:
        print("Connection error:", e)


def login(session):
    """
    Log in the user and cache the password and username in the session.
    """
    global SESSION_USERNAME
    print("\n--- Login ---")
    while True:
        username = input(
            'Enter username (only letters, numbers, and underscores) (Type "exit" to exit): ').strip()
        if is_valid_username(username) or username == "exit":
            if username == "exit":
                return
            break
        print("Invalid username. Please try again.")
    password = getpass.getpass("Enter password: ").strip()
    otp_input = input("Enter OTP code: ").strip()
    data = {"username": username, "password": password, "otp": otp_input}

    try:
        response = session.post(f"{SERVER_URL}/login", json=data)
        resp = response.json()

        if response.status_code == 200:
            print(resp.get("message"))
            SESSION_USERNAME = username
            return username
        else:
            print("Error:", resp.get("error"))

    except Exception as e:
        print("Connection error:", e)
        return None


def logout(session):
    global SESSION_USERNAME, KEY_PASSWORD
    try:
        response = session.post(f"{SERVER_URL}/logout")
        print(response.json().get("message"))
    except Exception as e:
        print("Connection error:", e)
    # Clear the cached session data
    SESSION_USERNAME = None
    KEY_PASSWORD = None
    # Don't reset login attempts on logout to maintain the lock


def upload_file(session):
    print("\n--- Upload File ---")
    file_path = input("Enter path of file to upload: ").strip()
    if not os.path.exists(file_path):
        print("File does not exist.")
        return
    filename = os.path.basename(file_path)
    # Read file data.
    with open(file_path, "rb") as f:
        file_data = f.read()
    # Generate a random 256-bit AES key.
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # recommended nonce size for AES-GCM.
    # Encrypt the file data. The result contains ciphertext and an authentication tag.
    encrypted_file_data = aesgcm.encrypt(nonce, file_data, None)
    # Prepend the nonce so that it is available for decryption.
    encrypted_file = nonce + encrypted_file_data
    # Get the public key from the server.
    public_key = get_public_key_from_server(session)
    if public_key is None:
        return
    # Encrypt the AES key with the retrieved RSA public key.
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Base64 encode the encrypted AES key for safe transport.
    enc_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    files = {
        'file': (filename, encrypted_file)
    }
    data = {
        'filename': filename,
        'enc_aes_key': enc_aes_key_b64
    }
    try:
        response = session.post(
            f"{SERVER_URL}/upload_file", data=data, files=files)
        print(response.json().get("message") or response.json().get("error"))
    except Exception as e:
        print("Connection error:", e)


def list_files(session):
    try:
        response = session.get(f"{SERVER_URL}/list_files")
        if response.status_code == 200:
            files = response.json().get("files", [])
            if not files:
                print("No files found.")
            else:
                print("\nYour files:")
                for f in files:
                    # If the 'sent_by' field exists and is non-empty, display it.
                    if "sent_by" in f and f["sent_by"]:
                        print(
                            f"ID: {f['id']}, Filename: {f['filename']} (Sent by: {f['sent_by']})")
                    else:
                        print(f"ID: {f['id']}, Filename: {f['filename']}")
            return files
        else:
            print("Error:", response.json().get("error"))
            return []
    except Exception as e:
        print("Connection error:", e)
        return []


def list_all_files(session):
    """
    Retrieves and displays all files that the logged-in user either owns or have been shared with.
    For each file, if it has been shared, the 'shared_by' field will be displayed.
    """
    try:
        response = session.get(
            f"{SERVER_URL}/list_all_files")
        if response.status_code == 200:
            files = response.json().get("files", [])
            if not files:
                print("No files found.")
            else:
                print("\nFiles available to you:")
                for f in files:
                    # For shared files, display who shared it.
                    if "sent_by" in f and f["sent_by"]:
                        print(
                            f"ID: {f['id']}, Filename: {f['filename']} (Sent by: {f['sent_by']})")
                    elif "shared_by" in f and f["shared_by"]:
                        print(
                            f"ID: {f['id']}, Filename: {f['filename']} (Shared by: {f['shared_by']})")
                    else:
                        print(
                            f"ID: {f['id']}, Filename: {f['filename']}")
            return files
        else:
            print("Error:", response.json().get("error"))
            return []
    except Exception as e:
        print("Connection error:", e)
        return []


def list_shared_users(session, file_id):
    """
    Lists the usernames with which a specified file has been shared.
    Only the owner of the file can retrieve this list.
    """
    if not file_id:
        print("File ID is required.")
        return

    try:
        response = session.get(
            f"{SERVER_URL}/list_shared_users?file_id={file_id}")
        if response.status_code == 200:
            data = response.json()
            shared_users = data.get("shared_users", [])
            if not shared_users:
                print("This file has not been shared with any user.")
            else:
                print(
                    f"\nThe file (ID: {file_id}) is shared with the following users:")
                for user in shared_users:
                    print(
                        f" - {user['target_username']}")
            return shared_users
        else:
            print("Error:", response.json().get("error"))
            return []
    except Exception as e:
        print("Connection error:", e)
        return []


def download_file(session):
    """
    Download a file from the server.
    Uses the cached password to load the RSA private key for decrypting the AES key.
    """
    print("\n--- Download File ---")
    files = list_all_files(session)
    if not files:
        return
    file_id = input("Enter the ID of the file to download: ").strip()
    try:
        data = {"file_id": file_id}
        response = session.post(f"{SERVER_URL}/download_file", json=data)
        if response.status_code != 200:
            print("Error:", response.json().get("error"))
            return
        resp = response.json()
        filename = resp.get("filename")
        enc_aes_key_b64 = resp.get("enc_aes_key")
        file_content_b64 = resp.get("file_content")

        # Decode the encrypted AES key and file content.
        encrypted_aes_key = base64.b64decode(enc_aes_key_b64)
        encrypted_file = base64.b64decode(file_content_b64)

        # Load the RSA private key using the cached password.
        private_key = load_rsa_private_key()
        if not private_key:
            print("Unable to load private key. Aborting download.")
            return

        # Decrypt the AES key using RSA OAEP.
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Extract the nonce (first 12 bytes) from the encrypted file.
        nonce = encrypted_file[:12]
        ciphertext = encrypted_file[12:]
        aesgcm = AESGCM(aes_key)
        decrypted_file = aesgcm.decrypt(nonce, ciphertext, None)

        # Save the decrypted file locally.
        output_path = f"downloaded_{filename}"
        with open(output_path, "wb") as f:
            f.write(decrypted_file)
        print(f"File downloaded and saved as {output_path}")
    except Exception as e:
        print("Error during download:", e)


def reset_password_logged_in(session):
    print("\n--- Reset Password ---")
    old_password = getpass.getpass("Enter current password: ").strip()

    while True:
        new_password = getpass.getpass(
            "Enter new password (min 10 characters): ").strip()
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            print(f"Invalid password: {error_msg}")
            continue
        break

    data = {"old_password": old_password, "new_password": new_password}
    try:
        response = session.post(f"{SERVER_URL}/reset_password", json=data)
        print(response.json().get("message") or response.json().get("error"))
    except Exception as e:
        print("Connection error:", e)


def edit_file(session):
    """
    Edit an existing file. The owner can update the filename and/or the file content.
    When updating the file content, the same AES key is used (i.e., it is not modified).
    """
    print("\n--- Edit File ---")
    # List files for the user
    files = list_files(session)
    if not files:
        return
    file_id = input("Enter the ID of the file you want to edit: ").strip()

    # Ask if the user wants to update the filename.
    new_filename = input(
        "Enter new filename (leave empty to keep current): ").strip()

    # Ask if the user wants to update the file content.
    update_content = input(
        "Do you want to update the file content? (y/n): ").strip().lower()

    update_data = {"file_id": file_id}
    if new_filename:
        update_data["filename"] = new_filename

    files_field = None

    if update_content == 'y':
        # Step 1: Download the file's metadata to retrieve the existing encrypted AES key.
        try:
            data = {"file_id": file_id}
            response = session.post(f"{SERVER_URL}/download_file", json=data)
            if response.status_code != 200:
                print("Error:", response.json().get("error"))
                return
            resp = response.json()
            current_enc_aes_key = resp.get("enc_aes_key")
            if not current_enc_aes_key:
                print("Error: File does not contain an AES key.")
                return
        except Exception as e:
            print("Error retrieving file info:", e)
            return

        # Step 2: Decrypt the current AES key using the owner's RSA private key.
        try:
            private_key = load_rsa_private_key()
            if not private_key:
                print("Unable to load private key. Aborting edit.")
                return
            original_aes_key = private_key.decrypt(
                base64.b64decode(current_enc_aes_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print("Error during AES key decryption:", e)
            return

        # Step 3: Read the new file content and encrypt it using the same AES key.
        new_file_path = input(
            "Enter the path of the new file content: ").strip()
        if not os.path.exists(new_file_path):
            print("File does not exist.")
            return
        try:
            with open(new_file_path, "rb") as f:
                new_file_data = f.read()
            # Generate a new nonce (AES-GCM requires a new nonce for each encryption).
            nonce = os.urandom(12)
            aesgcm = AESGCM(original_aes_key)
            new_encrypted_file = nonce + \
                aesgcm.encrypt(nonce, new_file_data, None)
            files_field = {"file": (os.path.basename(
                new_file_path), new_encrypted_file)}
        except Exception as e:
            print("Error during file encryption:", e)
            return

    try:
        response = session.post(
            f"{SERVER_URL}/edit_file", data=update_data, files=files_field)
        resp = response.json()
        print(resp.get("message") or resp.get("error"))
    except Exception as e:
        print("Connection error during file edit:", e)


def share_file(session):
    """
    Share a file with another user. The owner downloads their file's AES key,
    retrieves the target user's public key from the server, and re-encrypts the AES key.
    The resulting encrypted key is sent to the server to be stored in the file_shares table.
    """
    print("\n--- Share File ---")
    files = list_files(session)  # Lists files owned by the current user.
    if not files:
        return

    file_id = input("Enter the ID of the file you want to share: ").strip()
    target_username = input("Enter the username to share with: ").strip()

    # Client-side check: make sure the target is not the current user.
    if target_username == SESSION_USERNAME:
        print("Error: You cannot share a file with yourself.")
        return

    # Check if target user exists by reusing the /check_username endpoint.
    try:
        resp = session.get(
            f"{SERVER_URL}/check_username?username={target_username}")
        resp_json = resp.json()
        if not resp_json.get("exists", False):
            print(f"Error: User '{target_username}' does not exist.")
            return
    except Exception as e:
        print("Error checking target user's existence:", e)
        return

    # Step 1: Download the file to obtain the encrypted AES key.
    try:
        data = {"file_id": file_id}
        response = session.post(f"{SERVER_URL}/download_file", json=data)
        if response.status_code != 200:
            print("Error:", response.json().get("error"))
            return
        resp = response.json()
        enc_aes_key_b64 = resp.get("enc_aes_key")
        if not enc_aes_key_b64:
            print("Error: Missing AES key in download.")
            return
    except Exception as e:
        print("Error during file retrieval:", e)
        return

    # Step 2: Decrypt the AES key using the owner's private RSA key.
    try:
        private_key = load_rsa_private_key()
        if not private_key:
            print("Unable to load private key. Aborting share.")
            return
        original_aes_key = private_key.decrypt(
            base64.b64decode(enc_aes_key_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print("Error during decryption:", e)
        return

    # Step 3: Retrieve the target user's public key.
    target_public_key = get_public_key_from_server(session, target_username)
    if target_public_key is None:
        print("Failed to retrieve target user's public key.")
        return

    # Step 4: Re-encrypt the original AES key using the target user's public key.
    try:
        new_encrypted_aes_key = target_public_key.encrypt(
            original_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        new_enc_aes_key_b64 = base64.b64encode(
            new_encrypted_aes_key).decode('utf-8')
    except Exception as e:
        print("Error during re-encryption:", e)
        return

    # Step 5: Submit the share request to the server.
    try:
        share_data = {
            "file_id": file_id,
            "target_username": target_username,
            "enc_aes_key": new_enc_aes_key_b64
        }
        response = session.post(f"{SERVER_URL}/share_file", data=share_data)
        print(response.json().get("message") or response.json().get("error"))
    except Exception as e:
        print("Connection error during file sharing:", e)


def unshare_file(session):
    print("\n--- Unshare File ---")
    files = list_files(session)  # Lists files owned by the current user.
    if not files:
        return
    file_id = input("Enter the ID of the file you want to unshare: ").strip()
    share_users = list_shared_users(session, file_id)
    if not share_users:
        return
    target_username = input("Enter the username to unshare from: ").strip()
    if not file_id or not target_username:
        print("File ID and target username are required.")
        return
    try:
        data = {"file_id": file_id, "target_username": target_username}
        response = session.post(f"{SERVER_URL}/unshare_file", json=data)
        if response.status_code == 200:
            print(response.json().get("message"))
        else:
            print("Error:", response.json().get("error"))
    except Exception as e:
        print("Connection error:", e)


def send_file(session):
    """
    Send one of the current user's files with a designated recipient.
    The function:
      1. Lists the current user's files and prompts for a file ID to send.
      2. Prompts for the target username.
      3. Downloads and decrypts the chosen file.
      4. Re-encrypts the file with a new AES key.
      5. Encrypts the new AES key with the target user's public key.
      6. Uploads the re-encrypted file and the new encrypted key to the server via the /send_file endpoint.
    """
    print("\n--- Send File ---")
    files = list_files(session)
    if not files:
        return
    original_file_id = input(
        "Enter the ID of the file you want to send: ").strip()
    target_username = input("Enter the username to send: ").strip()
    # Fetch the target user's public key from the server.
    target_public_key = get_public_key_from_server(
        session, target_username)
    if target_public_key is None:
        print("Failed to retrieve target user's public key.")
        return
    # Step 1: Download and decrypt the file using the current user's keys.
    try:
        data = {"file_id": original_file_id}
        response = session.post(f"{SERVER_URL}/download_file", json=data)
        if response.status_code != 200:
            print("Error:", response.json().get("error"))
            return
        resp = response.json()
        filename = resp.get("filename")
        enc_aes_key_b64 = resp.get("enc_aes_key")
        file_content_b64 = resp.get("file_content")
        # Decode the encrypted AES key and file data.
        encrypted_aes_key = base64.b64decode(enc_aes_key_b64)
        encrypted_file = base64.b64decode(file_content_b64)
        # Load own RSA private key.
        private_key = load_rsa_private_key()
        if not private_key:
            print("Unable to load private key. Aborting share.")
            return
        # Decrypt the original AES key.
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decrypt the file using AES-GCM.
        nonce = encrypted_file[:12]
        ciphertext = encrypted_file[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print("Error during file decryption:", e)
        return

    # Step 2: Re-encrypt the file for the target user.
    try:
        # Generate a new AES key for the target user.
        new_aes_key = AESGCM.generate_key(bit_length=256)
        new_aesgcm = AESGCM(new_aes_key)
        new_nonce = os.urandom(12)
        new_encrypted_file_data = new_aesgcm.encrypt(
            new_nonce, plaintext, None)
        new_encrypted_file = new_nonce + new_encrypted_file_data
        # Encrypt the new AES key with the target user's public key.
        new_encrypted_aes_key = target_public_key.encrypt(
            new_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        new_enc_aes_key_b64 = base64.b64encode(
            new_encrypted_aes_key).decode('utf-8')
    except Exception as e:
        print("Error during file re-encryption:", e)
        return

    # Step 3: Upload the re-encrypted file as a shared file.
    try:
        files_field = {"file": (filename, new_encrypted_file)}
        share_data = {
            "original_file_id": original_file_id,
            "target_username": target_username,
            "filename": filename,
            "enc_aes_key": new_enc_aes_key_b64
        }
        response = session.post(
            f"{SERVER_URL}/send_file", data=share_data, files=files_field)
        print(response.json().get("message") or response.json().get("error"))
    except Exception as e:
        print("Connection error during file sending:", e)


def delete_file(session):
    print("\n--- Delete File ---")
    files = list_files(session)
    if not files:
        return
    file_id = input("Enter the ID of the file to delete: ").strip()
    confirm = input(
        "Are you sure you want to delete this file? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Deletion cancelled.")
        return
    try:
        data = {"file_id": file_id}
        response = session.post(f"{SERVER_URL}/delete_file", json=data)
        if response.status_code == 200:
            print(response.json().get("message"))
        else:
            print("Error:", response.json().get("error"))
    except Exception as e:
        print("Connection error:", e)


def view_logs(session):
    try:
        response = session.get(f"{SERVER_URL}/get_logs")
        if response.status_code == 200:
            logs = response.json().get("logs", [])
            for log in logs:
                print(
                    f"{log['timestamp']} - {log['username']} - {log['operation']} - {log['details']}")
                # print(
                #     f"{log['timestamp']} - {log['username']} - {log['operation']} - {log['details']} (Hash: {log['log_hash']})")
        else:
            print("Error:", response.json().get("error"))
    except Exception as e:
        print("Connection error:", e)


def main():
    # Using a persistent requests.Session to store cookies.
    session = requests.Session()
    # only for development
    session.verify = "cert.pem"
    while True:
        if not SESSION_USERNAME:
            print_menu_logged_out()
            choice = input("Enter choice: ").strip()
            if choice == '1':
                register()
            elif choice == '2':
                login(session)
            elif choice == '3':
                print("Exiting application.")
                break
            else:
                print("Invalid choice. Try again.")
        elif SESSION_USERNAME == "admin":
            print_menu_admin()
            choice = input("Enter choice: ").strip()
            if choice == '1':
                view_logs(session)
            elif choice == '2':
                logout(session)
            else:
                print("Invalid choice. Try again.")
        else:
            print_menu_logged_in()
            choice = input("Enter choice: ").strip()
            if choice == '1':
                upload_file(session)
            elif choice == '2':
                list_all_files(session)
            elif choice == '3':
                download_file(session)
            elif choice == '4':
                edit_file(session)
            elif choice == '5':
                share_file(session)
            elif choice == '6':
                unshare_file(session)
            elif choice == '7':
                send_file(session)
            elif choice == '8':
                delete_file(session)
            elif choice == '9':
                reset_password_logged_in(session)
            elif choice == '10':
                logout(session)
            else:
                print("Invalid choice. Try again.")


if __name__ == '__main__':
    main()
