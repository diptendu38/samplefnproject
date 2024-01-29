import string
import secrets
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import pad


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
                data_with_iv = ivector + data.encode('utf-8')
                cipher = AES.new(key, AES.MODE_CBC, ivector)
                padded_data = pad(data_with_iv, AES.block_size)
                encrypted_data = cipher.encrypt(padded_data)
                return encrypted_data
            except Exception as exp:
                print(f"Exception occurred: {exp}")
                return None


    def encode(self, value):
        if value is not None:
            return base64.b64encode(value).decode('utf-8')
        else:
            print("Encryption failed. Cannot encode None value.")
            return ''


    def generate_request_signature_encrypted_value(self, jwt_token):
        symmetric_key_value = self.generate_random(32)
        ivector = self.generate_random_ivector()
        aes_encryption_data = self.encrypt(jwt_token, symmetric_key_value.encode(), ivector)

        print(f"AES Symmetric Key: {symmetric_key_value}")
        request_signature_encrypted_value = self.encode(aes_encryption_data)
        print(f"Request Signature Encrypted Value: {request_signature_encrypted_value}")
        return request_signature_encrypted_value, symmetric_key_value
