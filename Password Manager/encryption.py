import base64
from Crypto.Cipher import AES


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
