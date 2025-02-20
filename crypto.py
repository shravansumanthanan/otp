import os
import binascii
import json
from datetime import datetime
from typing import Tuple, Optional
from pathlib import Path

class CryptoHandler:
    KEYS_FILE = 'keys.json'

    @staticmethod
    def generate_random_key(length: int) -> bytes:
        return os.urandom(length)

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @classmethod
    def store_key(cls, key_hex: str, ciphertext_hex: str) -> None:
        key_data = {
            'key': key_hex,
            'ciphertext': ciphertext_hex,
            'timestamp': datetime.now().isoformat()
        }
        with open(cls.KEYS_FILE, 'a') as f:
            json.dump(key_data, f)
            f.write('\n')

    @classmethod
    def get_stored_key(cls, ciphertext_hex: str) -> Optional[str]:
        if not Path(cls.KEYS_FILE).exists():
            return None
        
        with open(cls.KEYS_FILE, 'r') as f:
            return next(
                (json.loads(line)['key'] 
                 for line in f 
                 if json.loads(line)['ciphertext'] == ciphertext_hex),
                None
            )

    @classmethod
    def encrypt(cls, plaintext: str) -> Tuple[str, str]:
        plaintext_bytes = plaintext.encode()
        key = cls.generate_random_key(len(plaintext_bytes))
        ciphertext = cls.xor_bytes(plaintext_bytes, key)
        ciphertext_hex = binascii.hexlify(ciphertext).decode()
        key_hex = binascii.hexlify(key).decode()
        cls.store_key(key_hex, ciphertext_hex)
        return ciphertext_hex, key_hex

    @staticmethod
    def decrypt(ciphertext_hex: str, key_hex: str) -> str:
        ciphertext = binascii.unhexlify(ciphertext_hex)
        key = binascii.unhexlify(key_hex)
        plaintext_bytes = bytes(x ^ y for x, y in zip(ciphertext, key))
        return plaintext_bytes.decode()

def main():
    crypto = CryptoHandler()
    
    while True:
        user_input = input("Enter text to encrypt (or 'q' to quit): ").strip()
        if user_input.lower() == 'q':
            break
        
        try:
            ciphertext_hex, key_hex = crypto.encrypt(user_input)
            print(f"\nCiphertext (Hex): {ciphertext_hex}")
            print(f"Key (Hex): {key_hex}")
            
            decrypted = crypto.decrypt(ciphertext_hex, key_hex)
            print(f"Decrypted Text: {decrypted}\n")
            
        except Exception as e:
            print(f"Error: {e}\n")

if __name__ == "__main__":
    main()