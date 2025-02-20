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
        print("\nOptions:")
        print("  e - Encrypt text")
        print("  d - Decrypt text")
        print("  q - Quit")
        option = input("Select an option: ").strip().lower()

        if option == 'q':
            break
        
        if option == 'e':
            plaintext = input("Enter text to encrypt: ").strip()
            try:
                ciphertext_hex, key_hex = crypto.encrypt(plaintext)
                print(f"\nCiphertext (Hex): {ciphertext_hex}")
                print(f"Key (Hex): {key_hex}\n")
            except Exception as e:
                print(f"Error: {e}\n")
        
        elif option == 'd':
            ciphertext_hex = input("Enter ciphertext (Hex): ").strip()
            key_hex = input("Enter key (Hex) or press enter to retrieve stored key: ").strip()
            if not key_hex:
                key_hex = crypto.get_stored_key(ciphertext_hex)
                if key_hex is None:
                    print("No stored key found for this ciphertext.\n")
                    continue
            try:
                decrypted_text = crypto.decrypt(ciphertext_hex, key_hex)
                print(f"\nDecrypted Text: {decrypted_text}\n")
            except Exception as e:
                print(f"Error: {e}\n")
        
        else:
            print("Invalid option. Please try again.\n")

if __name__ == "__main__":
    main()
