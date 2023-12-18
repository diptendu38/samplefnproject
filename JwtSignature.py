import oci
import base64
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def read_key_from_vault(key_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        
        client = oci.secrets.SecretsClient({}, signer=signer)
        key_content = client.get_secret_bundle(key_ocid).data.secret_bundle_content.content.encode('utf-8')
        key_bytes = base64.b64decode(key_content)
    except Exception as ex:
        print("ERROR: failed to retrieve the key from the vault", ex, flush=True)
        raise
    return key_bytes

def jwt_signature(raw_data, private_key_ocid):
    private_key_bytes = read_key_from_vault(private_key_ocid)
    #public_key_bytes = read_key_from_vault(public_key_ocid)

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )


    header = {
        'alg': 'RS256',
        'typ': 'JWT'
    }

    jwt_token = jwt.encode(raw_data, private_key, algorithm='RS256', headers=header)

    print(f"\nDigitally Signed JWT: {jwt_token}")
    return jwt_token