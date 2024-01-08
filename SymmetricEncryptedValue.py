'''from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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

def encrypt_with_public_key(data, public_key):
    cipher_text = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

def symmetrickeyEncryption(data, public_key_ocid):
    public_key_bytes = read_key_from_vault(public_key_ocid)
    data_bytes = data.encode('utf-8')

    bank_public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    if bank_public_key is not None:
        encrypted_data = encrypt_with_public_key(data_bytes, bank_public_key)

        if encrypted_data is not None:
            encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            return encrypted_base64
        else:
            print("Encryption failed.")
            return ''
    else:
        print("Public key loading failed.")
        return ''
'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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

def encrypt_with_public_key(data, public_key):
    cipher_text = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text #recent

def symmetrickeyEncryption(data, public_key_ocid):
    public_key_bytes = read_key_from_vault(public_key_ocid)
    data_bytes = data.encode('utf-8')

    bank_public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    if bank_public_key is not None:
        encrypted_data = encrypt_with_public_key(data_bytes, bank_public_key)

        if encrypted_data is not None:
            encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            return encrypted_base64
        else:
            print("Encryption failed.")
            return ''
    else:
        print("Public key loading failed.")
        return ''




