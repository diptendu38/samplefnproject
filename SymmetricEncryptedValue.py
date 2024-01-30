from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64
import oci

def read_key_from_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        cert_content = client.get_secret_bundle(cert_ocid).data.secret_bundle_content.content
        cert_bytes = base64.b64decode(cert_content)
        public_key = RSA.import_key(cert_bytes)
        return public_key
    except Exception as ex:
        print("ERROR: failed to retrieve the certificate from the vault - {}".format(ex))
        raise

def encrypt_with_public_key(data, public_key):
        cipher = PKCS1_v1_5.new(public_key)
        if isinstance(data, str):
            message_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            message_bytes = data
        else:
            raise ValueError("Unsupported data type. Please provide a string or bytes.")
        chunk_size = 245
        chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

        encrypted_data = b""
        for chunk in chunks:
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_data += encrypted_chunk
        return encrypted_data

def symmetrickeyEncryption(data, public_key_ocid):
    #public_key_bytes = read_key_from_vault(public_key_ocid)
    public_key = read_key_from_vault(public_key_ocid)

    data_bytes = data.encode('utf-8')

    if bank_public_key is not None:
        encrypted_data = encrypt_with_public_key(data_bytes, public_key)

        if encrypted_data is not None:
            encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            return encrypted_base64
        else:
            print("Encryption failed.")
            return ''
    else:
        print("Public key loading failed.")
        return ''
