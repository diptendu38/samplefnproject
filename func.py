import json
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
    )
