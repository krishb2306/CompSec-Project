from cryptography.fernet import Fernet
import json
import os

class EncryptedStorage:
    def __init__(self, key_file='data/secret.key'):
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def save_encrypted(self, filename, data):
        """Save encrypted JSON data"""
        json_data = json.dumps(data) 
        encrypted = self.cipher.encrypt(json_data.encode())
        with open(filename, 'wb') as f:
            f.write(encrypted)

    def load_encrypted(self, filename):
        """Load and decrypt JSON data"""
        try:
            with open(filename, 'rb') as f:
                encrypted = f.read()
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Warning: Could not load/decrypt {filename}: {e}")
            return []