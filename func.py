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

import oci
import base64

def fetch_secret_from_vault(secret_ocid):
    # Set up OCI Vault client
    vault_client = oci.secrets.SecretsClient({})

    # Fetch the secret content
    secret_content = vault_client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content

    return secret_content

def handle(ctx, data: bytes = None):
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


