import string
import secrets
from Crypto.Cipher import AES
import base64

class RequestSignatureEncryptedValue:
    IVECTOR_LENGTH = 16

    def generate_random_ivector(self):
        characters = string.ascii_letters + string.digits
        random_ivector = ''.join(secrets.choice(characters) for _ in range(self.IVECTOR_LENGTH))
        return random_ivector.encode('utf-8')

    def generate_random(self, length):
        characters = string.ascii_letters + string.digits
        random_key = ''.join(secrets.choice(characters) for _ in range(length))
        return random_key

    def encrypt(self, data, key, ivector):
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv=ivector)
            data_bytes = data.encode('utf-8')
            padded_data = data_bytes + b'\0' * (16 - len(data_bytes) % 16)
            iv_and_data = ivector + padded_data
            encrypted_value = cipher.encrypt(iv_and_data)
            return encrypted_value
        except Exception as exp:
            print(f"Exception occurred during encryption: {exp}")
            return b''  

    def encode(self, value):
        if value is not None:
            return base64.b64encode(value)
        else:
            print("Encryption failed. Cannot encode None value.")
            return b''

    def generate_request_signature_encrypted_value(self, jwt_token):
        symmetric_key_value = self.generate_random(32)
        ivector = self.generate_random_ivector()
        aes_encryption_data = self.encrypt(jwt_token, symmetric_key_value.encode(), ivector)
        request_signature_encrypted_value = self.encode(aes_encryption_data).decode('utf-8')
        return request_signature_encrypted_value, symmetric_key_value

