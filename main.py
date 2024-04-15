import os
import sys
import getpass
import sys
import json
import hashlib
from cryptography.fernet import Fernet


def hello():
    with open('user_data.json', 'r') as file:
        data = json.load(file)

    return data


def hash_password(passd):
    password = passd.encode()
    return ((hashlib.sha256(password).hexdigest()))


def generateky():
    return Fernet.generate_key()


def intialize_chiper(key):
    return Fernet(key)


def encrypt_password(chiper, password):
    encodepass = password.encode()
    return chiper.encrypt(encodepass).decode()


def decrypt_password(chiper, encrypted_password):
    decrypted_password = chiper.decrypt(encrypted_password)
    return decrypted_password.decode()


def creatAccount(name, masterpassword):
    file_name = 'user_data.json'

    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        # File exists and is not empty
        with open(file_name, 'r') as file:
            data = json.load(file)

        # Check if the username already exists
        for entry in data:
            if entry['username'] == name:
                print("Username already exists. Please provide another name.")
                return

    else:
        # File doesn't exist or is empty, initialize data as an empty list
        data = []

    hashed_masterpassword = hash_password(masterpassword)
    user_data = {'username': name, 'masterpassword': hashed_masterpassword}

    # Append the new user data to the existing data
    data.append(user_data)

    # Write the updated data back to the file
    with open(file_name, 'w') as file:
        json.dump(data, file, indent=5)
        print("Account created successfully")


def login(username, usedpassword):
    file_name = 'user_data.json'
    try:
        # print("working..")
        with open(file_name, 'r') as file:
            user_data = json.load(file)
        # print(user_data)
        hasedusedpassword = hash_password(usedpassword)
        # print("hasedpassword",hasedusedpassword)
        # storedmasterpassword = user_data.get('masterpassword')
        # print("storedmasterpassword",storedmasterpassword)
        for entry in user_data:
            if entry['username'] == username and entry['masterpassword'] == hasedusedpassword:
                print("Login Successful.")
                return True
        print("Login Unsuccessfull!! Enter correct details.")

    except Exception:
        print("You have not Register..Please register first!")
        return False


# key generation
key_file_name = 'Encryption_key.key'
if os.path.exists(key_file_name):
    with open(key_file_name, 'rb') as key_file:
        key = key_file.read()
else:
    key = generateky()
    with open(key_file_name, 'wb') as key_file:
        key_file.write(key)
chiper = intialize_chiper(key)


def add_password(username, websitename, password):
    file_name = f'{username}_data.json'

    if not os.path.exists(file_name):
        data = []

    else:
        with open(file_name, 'r') as file:
            data = json.load(file)

    # to check if websitename already exist in the json file
    website_exits = False
    for entry in data:
        if entry['website'] == websitename:
            print("WebsiteName already exits")
            website_exits = True
            break
    if not website_exits:
        Encrypted_password = encrypt_password(chiper, password)
        password_entry = {'website': websitename,
                          'password': Encrypted_password}
        data.append(password_entry)

    with open(file_name, 'w') as file:
        json.dump(data, file, indent=5)


def get_password(website, username):
    file_name = f'{username}_data.json'

    if not os.path.exists(file_name):
        return None
    else:
        with open(file_name, 'r') as file:
            data = json.load(file)
    # print(data)

    for entry in data:
        if entry['website'] == website:
            var = entry['password']
            break

    decryptped_password = decrypt_password(chiper, entry['password'])
    print("The password is: ", decryptped_password)


def view_saved_websites(username):
    file_name = f'{username}_data.json'
    try:
        with open(file_name, 'r') as data:
            view = json.load(data)
            print("Your Saved Websites:")
            j = 1
            for entry in view:
                print(j, "->", entry['website'])
                j += 1

    except FileNotFoundError:
        print("You not have any website entries..please add it..")


def main():
    print("Welcome To My Password Management Tool")
    while True:
        print("To continue My Tool")
        print("1. Register[+]\n2. Login[->]\n3. Quit[x]")
        password_choice = input("Enter Your Choice: ")

        if password_choice == '1':
            username = input("Enter Username: ")
            password = getpass.getpass("Enter Password: ")
            creatAccount(username, password)

        if password_choice == '2':
            username = input("Enter Your UserName: ")
            password = getpass.getpass("Enter Your Registered Password: ")
            if login(username, password) == False:
                continue
            else:
                while True:
                    print("Enter Your Choice:")
                    print(
                        "1. AddPassword\n2. View Saved Websites\n3. Get Password\n4. Quit[X]")
                    user_choice = input("Enter Your Choice: ")
                    if user_choice == '1':
                        websitename = input("Enter Website Name: ")
                        password = getpass.getpass(
                            "Enter Your Password For {}: ".format(websitename))
                        add_password(username, websitename, password)

                    if user_choice == '2':
                        view_saved_websites(username)

                    if user_choice == '3':
                        website = input("Enter WebsiteName: ")
                        get_password(website, username)

                    if user_choice == '4':
                        print("Exiting Login..")
                        break

        if password_choice == '3':
            print("Thanks for used My Application")
            break


if __name__ == "__main__":
    main()
