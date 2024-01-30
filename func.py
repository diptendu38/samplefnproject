import io
import SymmetricDecrypt, Decrypt
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

    client_private_key_ocid = client_public_key_ocid = server_public_key_ocid = server_private_key_ocid = ""

    try:
        body = json.loads(data.getvalue())
        logging.getLogger().info("Request Body " + str(body))
        cfg = dict(ctx.Config())
        client_private_key_ocid = cfg["client_private_key_ocid"]
        logging.getLogger().info("Client Private Key OCID = " + client_private_key_ocid)
        client_public_key_ocid = cfg["client_public_key_ocid"]
        logging.getLogger().info("Client Public Key OCID = " + client_public_key_ocid)
        server_public_key_ocid = cfg["server_public_key_ocid"]
        logging.getLogger().info("Server Public Key OCID = " + server_public_key_ocid)
        server_private_key_ocid = cfg["server_private_key_ocid"]
        logging.getLogger().info("Server Private Key OCID = " + server_private_key_ocid)

    except Exception as e:
        print('ERROR: Missing configuration keys, client_private_key_ocid  client_public_key_ocid and server_public_key_ocid', e, flush=True)
        raise

    '''raw_data = {
        "BENE_ACC_NAME": "4272001002014063"
    }'''
    status_value = body["Type"]
    payload = body['Payload']
    json_response = {}

    if status_value == '1':
        jwt_token = JwtSignature.jwt_signature(payload, client_private_key_ocid)

        request_signature_encrypted_value_obj = Encrypt.RequestSignatureEncryptedValue()
        signature_encrypted_value, symmetric_key = request_signature_encrypted_value_obj.generate_request_signature_encrypted_value(jwt_token)
        symmetric_key_encrypted_value = SymmetricEncryptedValue.symmetrickeyEncryption(symmetric_key,server_public_key_ocid)

        json_response = create_json_payload(
                signature_encrypted_value,
                symmetric_key_encrypted_value,
            )
    elif status_value == '2':
        if not payload:
            json_response = {"error": "No JSON payload provided"}

        GWSymmetricKeyEncryptedValue = payload.get("GWSymmetricKeyEncryptedValue", "")
        ResponseSignatureEncryptedValue = payload.get("ResponseSignatureEncryptedValue", "")

        AES_key = SymmetricDecrypt.key_decryption_logic(GWSymmetricKeyEncryptedValue,server_private_key_ocid)
        logging.getLogger().info("AES Key = " + AES_key.decode('utf-8'))
        response_signature_decrypted_value_obj = Decrypt.Decryptor()
        json_response = response_signature_decrypted_value_obj.generate_response_signature_decrypted_value(AES_key, ResponseSignatureEncryptedValue,client_public_key_ocid)
    else :
        print("Returning status 500")
        json_response = {"error": "Status 500 - Internal Server Error"}
         
    logging.getLogger().info("function end")
    logging.getLogger().info("Response Payload %s" , json_response)

    return response.Response(
        ctx, 
        response_data=json.dumps(json_response, ensure_ascii=False, indent=2),
        headers={"Content-Type": "application/json"}
    )



