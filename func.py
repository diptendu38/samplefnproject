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


