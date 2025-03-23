# Angus

import requests

SERVER_URL = 'http://127.0.0.1:5000'

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# DEBUG
username = 'default_username' # User name (default)
password = b'default_password' # User password (default)
# DEBUG

def encryptFunction(data):
    salt = os.urandom(16) # Generate the 16 bytes (128 bits) random data as the salt

    # Use PBKDF2HMAC to generate the secret key
    kdf = PBKDF2HMAC(algorithms=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    AES_k = kdf.derive(password)

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
    kdf = PBKDF2HMAC(algorithms=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    AES_k = kdf.derive(password)

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
    with open(filePath, 'rb') as f: # Open the file in binary read mode
        files = {'file': f}
        data = {'username': username}
        response = requests.post(f"{SERVER_URL}/upload", files=files, data=data)
    
    return response

def downloadFileFromServer():
    # NOT FINISH
    return

# DEBUG
filePath = input("Enter file path: ").strip()
response = uploadFileToServer(filePath, username)
print(f'Server response: {response.status_code} - {response.json()}')
# DEBUG