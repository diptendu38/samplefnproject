from fdk import response
import json
import io
from Request import construct_request  

def handler(ctx, data: io.BytesIO=None):
    try:
        body = json.loads(data.getvalue())
        Response_to_oic = construct_request(body)
    except (Exception, ValueError) as ex:
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"Error: {str(ex)}"}),
            headers={"Content-Type": "application/json"},
            status=500  
        )

    return response.Response(
        ctx, response_data=json.dumps(Response_to_oic),
        headers={"Content-Type": "application/json"}
    )
