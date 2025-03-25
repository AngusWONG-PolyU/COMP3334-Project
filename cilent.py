import requests
import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_URL = 'http://127.0.0.1:5000'

loggedInUsername = None
loggedInPassword = None
# Maximum login attempts allowed before temporary lockout
MAX_LOGIN_ATTEMPTS = 3
# Dictionary to store login attempts by username
login_attempts = {}

def print_menu():
    if loggedInUsername:
        print("\n=== Online Storage Application Client ===")
        print(f"[Logged in as: {loggedInUsername}]")
        print("1. Reset Password")
        print("2. Upload File")
        print("3. Download File")
        print("4. Logout")
        print("5. Quit")
    else:
        print("\n=== Online Storage Application Client ===")
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        print("4. (DEBUGGING for upload file)")
        print("5. (DEBUGGING for download file)")


def register():
    print("\n--- Register ---")
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ").strip()
    
    # Check password length
    if len(password) < 10:
        print("Error: Password must be at least 10 characters long.")
        return
        
    password_confirm = getpass.getpass("Confirm password: ").strip()
    
    # Password confirmation check
    if password != password_confirm:
        print("Error: Passwords do not match.")
        return
        
    data = {"username": username, "password": password}
    try:
        response = requests.post(f"{SERVER_URL}/register", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
        else:
            print("Error:", response.json().get(
                "error", "Registration failed."))
    except Exception as e:
        print("Connection error:", e)


def login():
    global loggedInUsername 
    global loggedInPassword
    print("\n--- Login ---")
    username = input("Enter username: ").strip()
    
    # Check if account is locked due to too many failed attempts
    if username in login_attempts and login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
        print(f"Error: Account temporarily locked due to {MAX_LOGIN_ATTEMPTS} failed login attempts.")
        print("Please try again later or reset your password.")
        return
    
    password = getpass.getpass("Enter password: ").strip()
    data = {"username": username, "password": password}
    try:
        response = requests.post(f"{SERVER_URL}/login", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
            loggedInUsername = username 
            loggedInPassword = password
            # Reset login attempts on successful login
            if username in login_attempts:
                login_attempts[username] = 0
        else:
            # Increment failed login attempts
            if username not in login_attempts:
                login_attempts[username] = 1
            else:
                login_attempts[username] += 1
                
            attempts_left = MAX_LOGIN_ATTEMPTS - login_attempts[username]
            if attempts_left > 0:
                print(f"Error: {response.json().get('error', 'Login failed.')} ({attempts_left} attempts remaining)")
            else:
                print(f"Error: Maximum login attempts reached. Account temporarily locked.")
    except Exception as e:
        print("Connection error:", e)


def reset_password():
    print("\n--- Reset Password ---")
    username = input("Enter username: ").strip()
    old_password = getpass.getpass("Enter current password: ").strip()
    new_password = getpass.getpass("Enter new password: ").strip()
    
    # Check password length
    if len(new_password) < 10:
        print("Error: Password must be at least 10 characters long.")
        return
        
    confirm_password = getpass.getpass("Confirm new password: ").strip()
    
    # Password confirmation check
    if new_password != confirm_password:
        print("Error: New passwords do not match.")
        return
        
    data = {"username": username, "old_password": old_password,
            "new_password": new_password}
    try:
        response = requests.post(f"{SERVER_URL}/reset_password", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
            # Reset login attempts after successful password reset
            if username in login_attempts:
                login_attempts[username] = 0
        else:
            print("Error:", response.json().get(
                "error", "Password reset failed."))
    except Exception as e:
        print("Connection error:", e)

def encryptFunction(data):
    salt = os.urandom(16) # Generate the 16 bytes (128 bits) random data as the salt

    # Use PBKDF2HMAC to generate the secret key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    AES_k = kdf.derive(loggedInPassword.encode()) # Use the logged-in password as the password for PBKDF2HMAC

    AES_iv = os.urandom(16) # Generate the 16 bytes (128 bits) random data as the initialization vector of AES

    cipher = Cipher(algorithms.AES(AES_k), modes.CBC(AES_iv))
    encryptor = cipher.encryptor()

    padLength = 16 - (len(data) % 16) # Calculate the number of bytes needed for padding to ensure the data length is a multiple of 16 bytes
    data = data + bytes([0] * (padLength - 1)) + bytes([padLength]) # Use ZeroLength to pad the data

    ciphertext = encryptor.update(data) + encryptor.finalize()

    encryptedData = salt + AES_iv + ciphertext

    return encryptedData

def decryptFunction(encryptedData):
    salt = encryptedData[:16] # Get the first 16 bytes of encryptedData as the salt
    AES_iv = encryptedData[16:32] # Get the next 16 bytes of encryptedData as the initialization vector
    ciphertext = encryptedData[32:] # Get the remaining of encryptedData as the ciphertext

    # Use PBKDF2HMAC to generate the secret key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    AES_k = kdf.derive(loggedInPassword.encode()) # Use the logged-in password as the password for PBKDF2HMAC

    cipher = Cipher(algorithms.AES(AES_k), modes.CBC(AES_iv))
    decryptor = cipher.decryptor()
    decryptedData = decryptor.update(ciphertext) + decryptor.finalize()

    padLength = decryptedData[-1] # Get the padded length from the last byte of data

    return decryptedData[:-padLength] # Return the data without padding

def encryptFile(inputFile, outputFile):
    with open(inputFile, 'rb') as f: # Open the input file in binary read mode
        data = f.read() # Read the input file
        encryptedData = encryptFunction(data) # Encrypt the data of the input file
    
    with open(outputFile, 'wb') as f: # Open the output file in binary write mode
        f.write(encryptedData) # Write the encrypted data to the output file

def decryptFile(inputFile, outputFile):
    with open(inputFile, 'rb') as f: # Open the input file in binary read mode
        data = f.read() # Read the input file
        decryptedData = decryptFunction(data) # Decrypt the data of the input file
    
    with open(outputFile, 'wb') as f: # Open the output file in binary write mode
        f.write(decryptedData) # Write the decrypted data to the output file

def uploadFileToServer(filePath, username):
    encryptFile(filePath, filePath + '.enc')  # Encrypt the file before uploading
    filePath += '.enc'  # Change the file path to the encrypted file path
    try:
        with open(filePath, 'rb') as f:  # Open the file in binary read mode
            files = {'file': f}
            data = {'username': username}
            
            response = requests.post(f"{SERVER_URL}/upload", files=files, data=data)  # Send a POST request to the server
        
        response.raise_for_status()  # Check for HTTP errors
        return response.json()  # Return JSON response
    except Exception as e:
        return {'error': str(e)}
    finally:
        if os.path.exists(filePath):  # Ensure the encrypted file is deleted
            os.remove(filePath)

def downloadFileFromServer(username, filename):
    try:
        response = requests.get(f"{SERVER_URL}/download", params={'username': username, 'filename': filename})  # Send a GET request to the server
        response.raise_for_status()  # Check for HTTP errors
        encryptedFilePath = filename  # Create a temporary file path
        decryptedFilePath = encryptedFilePath[:-4]  # Remove the '.enc' extension from the filename
        with open(encryptedFilePath, 'wb') as f:
            f.write(response.content)  # Write the file content to a temporary file
        decryptFile(encryptedFilePath, decryptedFilePath)  # Decrypt the file after downloading
        os.remove(encryptedFilePath)  # Remove the temporary file
        return {'message': 'File downloaded successfully'}
    except Exception as e:
        return {'error': str(e)}

# DEBUG
def uploadFile():
    filePath = input("Enter file path: ").strip()
    response = uploadFileToServer(filePath, loggedInUsername)
    print(f'Server response: {response}')  # Print the server response

def downloadFile():
    filename = input("Enter filename: ").strip()
    response = downloadFileFromServer(loggedInUsername, filename + '.enc')
    print(f'Server response: {response}')  # Print the server response
# DEBUG

def main():
    global loggedInUsername, loggedInPassword
    while True:
        print_menu()
        if loggedInUsername:
            choice = input("Enter your choice (1-5): ").strip()
            if choice == '1':
                reset_password()
            elif choice == '2':
                uploadFile()
            elif choice == '3':
                downloadFile()
            elif choice == '4':
                print(f"Logging out user: {loggedInUsername}")
                loggedInUsername = None
                loggedInPassword = None
            elif choice == '5':
                print("Exiting the application.")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            choice = input("Enter your choice (1-5): ").strip()
            if choice == '1':
                register()
            elif choice == '2':
                login()
            elif choice == '3':
                print("Exiting the application.")
                break
            # DEBUG
            elif choice == '4':
                print("You must login first.")
            elif choice == '5':
                print("You must login first.")
            #DEBUG
            else:
                print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main()
