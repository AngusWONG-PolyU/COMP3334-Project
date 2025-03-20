import requests

SERVER_URL = 'http://127.0.0.1:5000'


def print_menu():
    print("\n=== Online Storage Application Client ===")
    print("1. Register")
    print("2. Login")
    print("3. Reset Password")
    print("4. Quit")


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
    print("\n--- Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    data = {"username": username, "password": password}
    try:
        response = requests.post(f"{SERVER_URL}/login", json=data)
        if response.status_code == 200:
            print("Success:", response.json().get("message"))
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
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main()
