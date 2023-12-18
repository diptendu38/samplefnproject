
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


import io
import json
import logging
import JwtSignature
import Encrypt
import SymmetricEncryptedValue
from fdk import response


def create_json_payload(resquest_signature_encrypted_value, symmetric_key_encrypted_value):
    payload = {
        "RequestSignatureEncryptedValue": resquest_signature_encrypted_value,
        "SymmetricKeyEncryptedValue": symmetric_key_encrypted_value
    }
    return payload

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    client_private_key_ocid = client_public_key_ocid = server_public_key_ocid = ""
    try:
        body = json.loads(data.getvalue())
        cfg = dict(ctx.Config())
        client_private_key_ocid = cfg["client_private_key_ocid"]
        logging.getLogger().info("Client Private Key OCID = " + client_private_key_ocid)
        #client_private_key_ocid = cfg["client_public_key_ocid"]
        #logging.getLogger().info("Client Public Key OCID = " + client_public_key_ocid)
        server_public_key_ocid = cfg["server_public_key_ocid"]
        logging.getLogger().info("Server Public Key OCID = " + server_public_key_ocid)
    except Exception as e:
        print('ERROR: Missing configuration keys, client_private_key_ocid  client_public_key_ocid and server_public_key_ocid', e, flush=True)
        raise

    '''raw_data = {
        "BENE_ACC_NAME": "4272001002014063"
    }'''

    jwt_token = JwtSignature.jwt_signature(body, client_private_key_ocid)

    request_signature_encrypted_value_obj = Encrypt.RequestSignatureEncryptedValue()
    signature_encrypted_value, symmetric_key = request_signature_encrypted_value_obj.generate_request_signature_encrypted_value(jwt_token)
    symmetric_key_encrypted_value = SymmetricEncryptedValue.symmetrickeyEncryption(symmetric_key,server_public_key_ocid)

    json_payload = create_json_payload(
            signature_encrypted_value,
            symmetric_key_encrypted_value,
        )

    logging.getLogger().info("function end")
    return response.Response(
        ctx, 
        response_data=json_payload,
        headers={"Content-Type": "application/json"}
    )



