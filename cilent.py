import requests
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_URL = 'http://127.0.0.1:5000'

loggedInUsername = None
loggedInPassword = None

def print_menu():
    print("\n=== Online Storage Application Client ===")
    print("1. Register")
    print("2. Login")
    print("3. Reset Password")
    print("4. Quit")
    print("5. (DEBUGGING for upload file)")
    print("6. (DEBUGGING for download file)")


def register():
    print("\n--- Register ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
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
    global loggedInUsername # Use the global variable to store the logged-in username
    global loggedInPassword # Use the global variable to store the logged-in password
    print("\n--- Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    data = {"username": username, "password": password}
    try:
        response = requests.post(f"{SERVER_URL}/login", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
            loggedInUsername = username # Store the logged-in username
            loggedInPassword = password # Store the logged-in password
        else:
            print("Error:", response.json().get("error", "Login failed."))
    except Exception as e:
        print("Connection error:", e)


def reset_password():
    print("\n--- Reset Password ---")
    username = input("Enter username: ").strip()
    old_password = input("Enter current password: ").strip()
    new_password = input("Enter new password: ").strip()
    data = {"username": username, "old_password": old_password,
            "new_password": new_password}
    try:
        response = requests.post(f"{SERVER_URL}/reset_password", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
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
    while True:
        print_menu()
        choice = input("Enter your choice (1-4): ").strip()
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            reset_password()
        elif choice == '4':
            print("Exiting the application.")
            break
        # DEBUG
        elif choice == '5':
            uploadFile()
        elif choice == '6':
            downloadFile()
        #DEBUG
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main()
