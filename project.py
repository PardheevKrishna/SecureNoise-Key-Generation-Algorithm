import re
import sys
sys.stdout.reconfigure(encoding='utf-8')  

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64
import librosa

def extract_allowed_characters(text):
    """
    Extracts allowed characters from text.

    Args:
        text (str): Input text.

    Returns:
        str: Allowed characters extracted from the text.
    """
    allowed_chars = re.findall(r'[a-zA-Z0-9 \t!@#$%^&*()-=_+{}|:"<>?,./;\'\\[\]`~]', text)
    return ''.join(allowed_chars)

def extract_key_from_audio_text(n, audio_text, allowed_characters):
    """
    Combines keys extracted from audio text and text data.

    Args:
        n (int): Length of the combined key.
        audio_text (str): Text extracted from the audio.
        allowed_characters (str): Allowed characters extracted from text data.

    Returns:
        bytes: Combined key.
    """
    keyLen = len(audio_text) // 3
    audio_key = audio_text[keyLen : keyLen + n // 2]
    text_key = allowed_characters[:n // 2]
    combined_key = audio_key + text_key.encode()
    return combined_key

def pad(data):
    """
    Pads data to make its length a multiple of 16 bytes.

    Args:
        data (bytes): Data to pad.

    Returns:
        bytes: Padded data.
    """
    length = 16 - (len(data) % 16)
    return data + bytes([length] * length)

def unpad(data):
    """
    Removes padding from data.

    Args:
        data (bytes): Data to unpad.

    Returns:
        bytes: Unpadded data.
    """
    return data[:-data[-1]]

def generate_aes_key(derived_key):
    """
    Generates AES key from derived key.

    Args:
        derived_key (bytes): Derived key.

    Returns:
        bytes: AES key.
    """
    hashed_key = hashlib.sha256(derived_key).digest()
    aes_key = hashed_key[:16]  
    return aes_key

def aes_encrypt_with_combined_key(message, combined_key):
    """
    Encrypts message using combined key.

    Args:
        message (str): Message to encrypt.
        combined_key (bytes): Combined key.

    Returns:
        str: Encrypted message in Base64 encoding.
    """
    padded_message = pad(message.encode('utf-8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(combined_key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(padded_message)
    encrypted_message_base64 = base64.b64encode(iv + encrypted_message).decode('utf-8')
    return encrypted_message_base64

def aes_decrypt_with_combined_key(encrypted_message_base64, combined_key):
    """
    Decrypts message using combined key.

    Args:
        encrypted_message_base64 (str): Encrypted message in Base64 encoding.
        combined_key (bytes): Combined key.

    Returns:
        str: Decrypted message.
    """
    encrypted_message = base64.b64decode(encrypted_message_base64.encode('utf-8'))
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(combined_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message[AES.block_size:])
    decrypted_message = unpad(decrypted_message).decode('utf-8')
    return decrypted_message

def mp3_to_key(mp3_file):
    """
    Converts an MP3 audio file to a key.

    Args:
        mp3_file (str): Path to the MP3 audio file.

    Returns:
        bytes: Key extracted from the audio file.
    """
    y, sr = librosa.load(mp3_file)
    key = y.tobytes()
    return key

# Usage
message = '''
She counted. One. She could hear the steps coming closer. Two. Puffs of breath could be seen coming from his mouth. Three. He stopped beside her. Four. She pulled the trigger of the gun.
The red ball sat proudly at the top of the toybox. It had been the last to be played with and anticipated it would be the next as well. The other toys grumbled beneath. At one time each had held the spot of the red ball, but over time they had sunk deeper and deeper into the toy box.
'''

print("\nOriginal Message:" + message)

mp3_file = "audio.mp3"
audio_data = mp3_to_key(mp3_file)

with open('audio.txt', 'r', encoding='utf-8') as file:
    text = file.read()

allowed_characters = extract_allowed_characters(text)

combined_key = extract_key_from_audio_text(len(message), audio_data, allowed_characters)
print("Combined Key (in hexadecimal):\n" + combined_key.hex())

aes_key = generate_aes_key(combined_key)

encrypted_text_with_combined_key = aes_encrypt_with_combined_key(message, aes_key)
print("\nEncrypted Text with Combined Key:\n" + encrypted_text_with_combined_key)

decrypted_text_with_combined_key = aes_decrypt_with_combined_key(encrypted_text_with_combined_key, aes_key)
print("\nDecrypted Text with Combined Key:" + decrypted_text_with_combined_key)
