from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import jwt
import oci

class Decryptor:
    
   # @staticmethod
    def decrypt(encrypted_value, key):
        try:
            ivector = encrypted_data[:16]
            cipher = AES.new(key, AES.MODE_CBC, ivector)
            decrypted_data = cipher.decrypt(encrypted_data[16:]) 
            unpadded_data = unpad(decrypted_data, AES.block_size)
            return unpadded_data.decode('utf-8')
        except ValueError as ve:
            print(f"Decryption failed: {ve}")
            return None
        except Exception as exp:
            print(f"Exception occurred during AES decryption: {exp}")
            return None

    def read_key_from_vault(key_ocid):
        signer = oci.auth.signers.get_resource_principals_signer()
        try:
            client = oci.secrets.SecretsClient({}, signer=signer)
            key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content.encode('utf-8')
            key_bytes = base64.b64decode(key_content)
        except Exception as ex:
            print("ERROR: failed to retrieve the key from the vault", ex)
            raise
        return key_bytes

    def generate_response_signature_decrypted_value(self,symmetric_key_value,request_signature_encrypted_value,public_key_ocid):
        decrypted_jws_token_bytes  = Decryptor.decrypt(base64.b64decode(request_signature_encrypted_value), symmetric_key_value.encode())

        if decrypted_jws_token_bytes  is not None:
            #    decrypted_jws_token = decrypted_jws_token_bytes.encode('utf-8')
            print(f"Decrypted JWS Token: {decrypted_jws_token_bytes}")
        else:
            print("Decryption failed.")

        public_key_bytes = Decryptor.read_key_from_vault(public_key_ocid)
        public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
        try:
            decoded_payload = jwt.decode(decrypted_jws_token, public_key, algorithms=['RS256'])
            return(decoded_payload)
        except jwt.ExpiredSignatureError:
            print("JWT has expired.")
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
