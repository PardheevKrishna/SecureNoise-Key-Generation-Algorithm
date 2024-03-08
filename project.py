import re
import sys
sys.stdout.reconfigure(encoding='utf-8')  # Replace 'utf-8' with the desired encoding

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64

def extract_allowed_characters(text):
    allowed_chars = re.findall(r'[a-zA-Z0-9 \t!@#$%^&*()-=_+{}|:"<>?,./;\'\\[\]`~]', text)
    return ''.join(allowed_chars)

def extract_key(n,key):
    keyLen = len(key) // 3
    key = key[keyLen : keyLen + n]
    return key

def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length] * length)

def unpad(data):
    return data[:-data[-1]]

def generate_aes_key(derived_key):
    hashed_key = hashlib.sha256(derived_key.encode()).digest()
    aes_key = hashed_key[:16]  # Truncate to 16 bytes for AES-128, adjust for AES-192 or AES-256
    return aes_key

def aes_encrypt(message, key):
    padded_message = pad(message.encode('utf-8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(padded_message)
    encrypted_message_base64 = base64.b64encode(iv + encrypted_message).decode('utf-8')
    return encrypted_message_base64

def aes_decrypt(encrypted_message_base64, key):
    encrypted_message = base64.b64decode(encrypted_message_base64.encode('utf-8'))
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message[AES.block_size:])
    decrypted_message = unpad(decrypted_message).decode('utf-8')
    return decrypted_message

message ='''
She counted. One. She could hear the steps coming closer. Two. Puffs of breath could be seen coming from his mouth. Three. He stopped beside her. Four. She pulled the trigger of the gun.
The red ball sat proudly at the top of the toybox. It had been the last to be played with and anticipated it would be the next as well. The other toys grumbled beneath. At one time each had held the spot of the red ball, but over time they had sunk deeper and deeper into the toy box.
'''

print("Message: " + message + '\n')

with open('audio.txt', 'r', encoding='utf-8') as file:
    text = file.read()

allowed_characters = extract_allowed_characters(text)

key = allowed_characters
key = extract_key(len(message), key)

with open('keys.txt', 'w') as output_file:
    output_file.write("Key: {}\n".format(key))

print("Key: " + key + '\n')

aes_key = generate_aes_key(key)

encrypted_text = aes_encrypt(message, aes_key)
print("Encrypted Text:", encrypted_text + '\n')

decrypted_text = aes_decrypt(encrypted_text, aes_key)
print("Decrypted Text:", decrypted_text)
