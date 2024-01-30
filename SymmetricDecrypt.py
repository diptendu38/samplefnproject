from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import oci

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

def decrypt_with_private_key(encrypted_data, private_key):
    try:
        cipher = PKCS1_v1_5.new(private_key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_data = cipher.decrypt(encrypted_bytes, None)
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return None

def key_decryption_logic(encrypted_base64, private_key_ocid):
    private_key_bytes = read_key_from_vault(private_key_ocid)

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    if private_key is not None:
        decrypted_data = decrypt_with_private_key(encrypted_base64,private_key)

        if decrypted_data is not None:
            return decrypted_data
        else:
            print("Decryption failed.")
            return b""
    else:
        print("Private key loading failed.")
