from cryptography.fernet import Fernet
import json
import os

class EncryptedStorage:
    def __init__(self, key_file='data/secret.key'):
        os.makedirs(os.path.dirname(key_file) if os.path.dirname(key_file) else '.', exist_ok=True)
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)

        self.cipher = Fernet(self.key)

    def save(self, filename, data):
        """Save data as encrypted JSON"""
        os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
        
        json_data = json.dumps(data, default=str) 
        encrypted = self.cipher.encrypt(json_data.encode())

        with open(filename, 'wb') as f:
            f.write(encrypted)

    def load(self, filename):
        """Load and decrypt JSON data, return empty list if file doesn't exist or is corrupt"""
        if not os.path.exists(filename):
            return []
        
        if os.path.getsize(filename) == 0:
            print(f"Warning: {filename} is empty, returning default")
            return []
        
        try:
            with open(filename, 'rb') as f:
                encrypted = f.read()
            
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as e:
        
            print(f"Warning: Could not decrypt {filename}: {e}")
            if os.path.exists(filename):
                backup_name = f"{filename}.corrupt"
                os.rename(filename, backup_name)
                print(f"Backed up corrupt file to {backup_name}")
            return []