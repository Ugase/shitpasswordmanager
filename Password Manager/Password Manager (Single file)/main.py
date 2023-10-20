import base64
from Crypto.Cipher import AES
import json
from secrets import choice
from string import digits, ascii_letters, punctuation

def encrypt(message, key):
  """Encrypts the given message using the given key.

  Args:
    message: The message to encrypt.
    key: The encryption key.

  Returns:
    The encrypted message.
  """
  message = message.encode("utf-8")
  padding_length = 16 - len(message) % 16
  padding = bytes([padding_length] * padding_length)
  padded_message = message + padding
  cipher = AES.new(key, AES.MODE_CBC, IV=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
  return base64.b64encode(cipher.encrypt(padded_message))

def decrypt(ciphertext, key):
  """Decrypts the given ciphertext using the given key.

  Args:
    ciphertext: The ciphertext to decrypt.
    key: The decryption key.

  Returns:
    The decrypted message.
  """
  cipher = AES.new(key, AES.MODE_CBC, IV=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
  decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
  padding_length = decrypted_message[-1]
  return decrypted_message[:-padding_length].decode("utf-8", "ignore")


def generator(num_of_chr:int) -> str:
  """Generates a random list of numbers, letters and symbols"""
  sbol_list = digits + ascii_letters + punctuation
  result = "".join(choice(sbol_list) for _ in range(num_of_chr))
  result.replace("\\", "")
  return result

def create_master_password(password: str):
    if len(password) % 32 != 0:
        raise ValueError(f"Password must be divisible by 32 not {len(password)}")
    with open("masterpassword.txt", "wb") as f:
        f.write(encrypt(password, bytes(password.encode("utf-8"))))


def verify_master_password(password: str):
  if len(password) % 32 != 0:
      raise ValueError(f"Password must be divisible by 32 not {len(password)}")
  key = bytes(password.encode("utf-8", "ignore"))
  with open("masterpassword.txt", "rb") as f:
      encrypted_master_password = f.read()
  decrypted_master_password = decrypt(encrypted_master_password, key)

  return password == decrypted_master_password

def ask_master_password():
  return input("Master password: ")

def print_error(message):
  """Prints an error message in red.

    Args:
        message (str): The error message.
    """
  print(f"\033[31m{message}\033[0m")
    


def ex():
    try:
        with open("passwords.json", "a") as f:
            if not f.read():
                f.write("{}")
    except FileNotFoundError:
        with open("passwords.json", "w") as f:
                f.write("{}")
    try:
        with open("masterpassword.txt") as f:
            if not f.read():
                return 2
            if f.read() and f.read >= 64:
                return 0
    except FileNotFoundError:
        return 1



if ex() == 0:
    while True:
        master_password = ask_master_password()
        if verify_master_password(master_password):
            break
        else:
            print_error("Wrong master password. Try again")

else:
    while True:
        master_password = input("A master password (Length must be divisible by 32): ")
        if len(master_password) % 32 == 0:
            create_master_password(master_password)
            break

with open("passwords.json", "r") as f:
    passwords = json.load(f)

def create_password(user_name: str, password: str):
    global passwords
    user_name = user_name.lower()
    passwords[user_name] = encrypt(password, bytes(master_password.encode("utf-8"))).decode("utf-8")
    print("Sucessfully added pasword")
    
def get_password(name: str):
  name = name.lower()
  return f"Name: {name.capitalize()} Password: {decrypt(passwords[name], master_password)}"


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
            generated_password = generator(length)
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
