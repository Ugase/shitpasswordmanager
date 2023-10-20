import storage_system as s
import encryption as e
import json
import password_generator as pg

# Code Part

def print_error(message):
    """Prints an error message in red.

    Args:
        message (str): The error message.
    """
    print(f"\033[31m{message}\033[0m")

if s.ex() == 0:
    while True:
        master_password = s.ask_master_password()
        if s.verify_master_password(master_password):
            break
        else:
            print_error("Wrong master password. Try again")

else:
    while True:
        master_password = input("A master password (Length must be divisible by 32): ")
        if len(master_password) % 32 == 0:
            s.create_master_password(master_password)
            break

with open("passwords.json", "r") as f:
    passwords = json.load(f)

def create_password(user_name: str, password: str):
    global passwords
    user_name = user_name.lower()
    passwords[user_name] = e.encrypt(password, bytes(master_password.encode("utf-8"))).decode("utf-8")
    print("Sucessfully added pasword")
    
def get_password(name: str):
    name = name.lower()
    return f"Name: {name.capitalize()} Password: {e.decrypt(passwords[name], master_password)}"


def list_passwords():
    for key, _ in passwords.items():
        print(get_password(key))


# UI
def main():
    while True:
        print("\033[1mWelcome to the Password Manager!\033[0m")
        print("\033[1mWhat would you like to do?\033[0m")
        print("\033[1m1. Add a password\033[0m")
        print("\033[1m2. Get a password\033[0m")
        print("\033[1m3. Generate Password\033[0m")
        print("\033[1m4. List all\033[0m")
        print("\033[1m5. Exit\033[0m")

        choice = input("Enter your choice: ")

        if choice == "1":
            print("\033[1mEnter the username: \033[0m")
            username = input()
            print("\033[1mEnter the password: \033[0m")
            password = input()
            create_password(username, password)
        elif choice == "2":
            print("\033[1mEnter the service name: \033[0m")
            while True:
                try:
                    service_name = input()
                    print(get_password(service_name))
                except KeyError:
                    print_error(f"There is no {service_name} Try again:\n")
        elif choice == "3":
            while True:
                try:
                    length = int(input("\033[1mLength of password: \033[0m"))
                    break
                except ValueError:
                    print_error("Only Numbers")
            generated_password = pg.generator(length)
            print(f"\033[1mGenerated password: {generated_password}\033[0m")
            continue
        elif choice == "4":
            list_passwords()
        
        elif choice == "5":
            print("\033[1mExiting...\033[0m")
            break

if __name__ == '__main__':
    main()

json_s = json.dumps(passwords, default=str)
with open("passwords.json", "w") as f:
    f.write(json_s)
