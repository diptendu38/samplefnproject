''''import json
from fdk import response

def handler(ctx, data: dict = None):
    try:
        name = data.get("Name", "")
        last = data.get("Last", "")
        full_name = f"{name} {last}"

        result = {"Full Name": full_name}
    except Exception as e:
        return response.Response(
            response_data=json.dumps({"error": str(e)}),
            headers={"Content-Type": "application/json"},
            status_code=500
        )

    return response.Response(
        response_data=json.dumps(result),
        headers={"Content-Type": "application/json"},
        status_code=200
    )'''


'''import io
import json

from fdk import response


def handler(ctx, data: io.BytesIO=None):
    print("Entering Python Hello World handler", flush=True)
    name = "World"
    try:
        body = json.loads(data.getvalue())
        name = body.get("Name")
        last = body.get("Last")
        full_name = f"{name} {last}"
        result = {"Full Name": full_name}
    except (Exception, ValueError) as ex:
            return response.Response(
            response_data=json.dumps({"error": str(e)}),
            headers={"Content-Type": "application/json"}
        )

    print("Vale of name = ", name, flush=True)
    print("Exiting Python Hello World handler", flush=True)

    return response.Response(
        ctx, response_data=json.dumps(result),
        headers={"Content-Type": "application/json"},
    )'''

'''import oci
import base64

def fetch_secret_from_vault(secret_ocid):
    # Set up OCI Vault client
    vault_client = oci.secrets.SecretsClient({})

    # Fetch the secret content
    secret_content = vault_client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content

    return secret_content

def handler(ctx, data: bytes = None):
    # Replace 'your_secret_ocid' with the actual OCID of your secret in OCI Vault
    secret_ocid = 'ocid1.vaultsecret.oc1.ap-mumbai-1.amaaaaaampahd3ianjpywinnvcdy5se5kidb25wsheuw5j5ddjznqvuvy6qq'

    try:
        # Fetch the secret content from OCI Vault
        secret_content = fetch_secret_from_vault(secret_ocid)

        # Decode the base64-encoded content (assuming the secret is a base64-encoded PEM key)
        decoded_content = base64.b64decode(secret_content).decode('utf-8')

        # Print the secret content
        print(f"Secret Content:\n{decoded_content}")

        return f"Secret Content:\n{decoded_content}"
    except oci.exceptions.ServiceError as e:
        print(f"Error fetching secret from OCI Vault: {e}")
        return f"Error fetching secret from OCI Vault: {e}"
'''
'''
import io
import json
import base64
import oci
import logging
import hashlib

from fdk import response

def get_text_secret(secret_ocid):
    #decrypted_secret_content = ""
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
        decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    return {"secret content": decrypted_secret_content}


def get_binary_secret_into_file(secret_ocid, filepath):
    #decrypted_secret_content = ""
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    try:
        with open(filepath, 'wb') as secretfile:
            decrypted_secret_content = base64.decodebytes(secret_content)
            secretfile.write(decrypted_secret_content)
        with open('/tmp/secret', 'rb') as file:
            content = file.read()
            print(content)

    except Exception as ex:
        print("ERROR: cannot write to file " + filepath, ex, flush=True)
        raise
    secret_md5 = hashlib.md5(decrypted_secret_content).hexdigest()
    return {"secret md5": secret_md5}


def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    secret_ocid = secret_type = resp = ""
    try:
        cfg = dict(ctx.Config())
        secret_ocid = cfg["secret_ocid"]
        logging.getLogger().info("Secret ocid = " + secret_ocid)
        secret_type = cfg["secret_type"]
        logging.getLogger().info("Secret type = " + secret_type)
    except Exception as e:
        print('ERROR: Missing configuration keys, secret ocid and secret_type', e, flush=True)
        raise

    if secret_type == "text":
        resp = get_text_secret(secret_ocid)
    elif secret_type == "binary":
        resp = get_binary_secret_into_file(secret_ocid, "/tmp/secret")
    else:
        raise ValueError('the value of the configuration parameter "secret_type" has to be either "text" or "binary"')

    logging.getLogger().info("function end")
    return response.Response(
        ctx, 
        response_data=resp,
        headers={"Content-Type": "application/json"}
    )
    '''
import io
import json
import base64
import oci
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fdk import response

def read_key_from_vault(key_ocid):
    # Assuming the key is stored as a text secret in OCI Vault
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

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    private_key_ocid = public_key_ocid = ""
    try:
        cfg = dict(ctx.Config())
        private_key_ocid = cfg["private_key_ocid"]
        logging.getLogger().info("Private Key OCID = " + private_key_ocid)
        #public_key_ocid = cfg["public_key_ocid"]
        #logging.getLogger().info("Public Key OCID = " + public_key_ocid)
    except Exception as e:
        print('ERROR: Missing configuration keys, private_key_ocid and public_key_ocid', e, flush=True)
        raise

    raw_data = {
        "BENE_ACC_NAME": "4272001002014063"
    }

    jwt_token = jwt_signature(raw_data, private_key_ocid)

    logging.getLogger().info("function end")
    return response.Response(
        ctx, 
        response_data={"jwt_token": jwt_token},
        headers={"Content-Type": "application/json"}
    )



