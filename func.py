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


import io
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
    )

