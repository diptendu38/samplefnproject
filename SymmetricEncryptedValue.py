import string
import base64
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad
import secrets
import oci

def generate_random(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

def encrypt_symmetric(key, init_vector, value):
    try:
        key_bytes = key.encode('utf-8')
        iv_bytes = init_vector.encode('utf-8')
        value_bytes = value.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_data = pad(value_bytes, AES.block_size)

        encrypted_data = cipher.encrypt(padded_data)

        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as ex:
        print(ex)

    return None

def encrypt_asymmetric(public_key,message):
    cipher = PKCS1_v1_5.new(public_key)
    message_bytes = message.encode('utf-8')
    chunk_size = 245
    chunks = [message_bytes[i:i + chunk_size] for i in range(0, len(message_bytes), chunk_size)]

    encrypted_data = b""
    for chunk in chunks:
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_data += encrypted_chunk

    return base64.b64encode(encrypted_data).decode('utf-8')

def read_key_from_vault(cert_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(cert_ocid).data.secret_bundle_content.content.encode('utf-8')
        key_bytes = base64.b64decode(key_content)
    except Exception as ex:
        print("ERROR: failed to retrieve the key from the vault", ex)
        raise
    return key_bytes

def encryption_logic(payload, cert_ocid):
    randomno = generate_random(16)
    init_vector = generate_random(16)
    iv_bytes = init_vector.encode('utf-8')
    public_key_bytes = read_key_from_vault(cert_ocid)
    
    bank_public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    encrypted_data = encrypt_symmetric(randomno.encode('utf-8'), iv_bytes, payload)
    encrypted_key = encrypt_asymmetric(bank_public_key, randomno)
    
    return encrypted_data,encrypted_key,base64.b64encode(iv_bytes).decode('utf-8')
