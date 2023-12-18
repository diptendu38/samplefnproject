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
        #symmetric_key_value = "sAAa5Yuj4tsmnU5DYzQ9qba9iqA9d9nS"
        ivector = self.generate_random_ivector()
        aes_encryption_data = self.encrypt(jwt_token, symmetric_key_value.encode(), ivector)
        #print(f"AES Encrypted Data: {aes_encryption_data}")
        request_signature_encrypted_value = self.encode(aes_encryption_data).decode('utf-8')
        #print(f"Request Signature Encrypted Value: {request_signature_encrypted_value}")
        return request_signature_encrypted_value, symmetric_key_value

'''if __name__ == "__main__":
    jwt_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJMT0dJTl9JRCI6IkFQSVVTRVJAQ0JYTUdSVDIiLCJJTlBVVF9HQ0lGIjoiQ0JYTUdSVDIiLCJUUkFOU0ZFUl9UWVBFX0RFU0MiOiJJTVBTIiwiQkVORV9CQU5LIjoiUFVOSkFCIE5BVElPTkFMIEJBTksiLCJJTlBVVF9ERUJJVF9BTU9VTlQiOiIzIiwiSU5QVVRfVkFMVUVfREFURSI6IjAzLzEwLzIwMjMiLCJUUkFOU0FDVElPTl9UWVBFIjoiU0lOR0xFIiwiSU5QVVRfREVCSVRfT1JHX0FDQ19OTyI6IjAxODEwNTMwMDAwNTM1IiwiSU5QVVRfQlVTSU5FU1NfUFJPRCI6IlZFTkRCVVMwMSIsIkJFTkVfSUQiOiIxMjM0NTY3ODkwIiwiQkVORV9BQ0NfTkFNRSI6IjQyNzIwMDEwMDIwMTQwNjMiLCJCRU5FX0FDQ19OTyI6IjEyMzQ1NjA0MSIsIkJFTkVfVFlQRSI6IkFESE9DIiwiQkVORV9CUkFOQ0giOiJNVU1CQUkgIEJBTkRSQSBLVVJMQSBDT01QTEVYIiwiQkVORV9JRE5fQ09ERSI6IkNJVEkwMDAwMDAxIiwiRU1BSUxfQUREUl9WSUVXIjoidHRkQGcuY29tIiwiUEFZTUVOVF9SRUZfTk8iOiJURVNUTkVGVDIxIn0.Q_EaMRS5WhMVf62w4kOnjj6dpSavkUL5wopSu3SRk862ArkpErgEWowztWpR1eJ8iIANEnTQFwmCKd-vWNQEQgAg-g5vJmHp97pplMvKCsCs4A3mmh2_P405FIEu7Tw2qm4lEhWuZ0c6tSSTV1FInYpU5z0gbEmbdQRlXhj0tSk_VtM1CQz2u3oVMZ37RQ1cAtvWM1tK4OCAIuAqrTff2CTa26nF-ajYwV1D2_vKR8nBk2RFaORQISOKN4Nkcq1smCx0MzL1HovEl5o4M-DX9TU8R-laWzuX7l_8hWJ0zh-La3Gm0bFemVs0R7OdbYm8-N9psF-0v2Zgt-ONW3arjA"

    request_signature_encrypted_value_obj = RequestSignatureEncryptedValue()
    encrypted_value, symmetric_key = request_signature_encrypted_value_obj.generate_request_signature_encrypted_value(jwt_token)'''

