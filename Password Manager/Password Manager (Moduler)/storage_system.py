import encryption as e


def ex():
    try:
        with open("passwords.json", "r") as f:
            if not f.read():
                with open("passwords.json", "w") as f:
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


def create_master_password(password: str):
    if len(password) % 32 != 0:
        raise ValueError(f"Password must be divisible by 32 not {len(password)}")
    with open("masterpassword.txt", "wb") as f:
        f.write(e.encrypt(password, bytes(password.encode("utf-8"))))


def verify_master_password(password: str):
    if len(password) % 32 != 0:
        raise ValueError(f"Password must be divisible by 32 not {len(password)}")
    key = bytes(password.encode("utf-8", "ignore"))
    with open("masterpassword.txt", "rb") as f:
        encrypted_master_password = f.read()
    decrypted_master_password = e.decrypt(encrypted_master_password, key)

    return password == decrypted_master_password

def ask_master_password():
    return input("Master password: ")

