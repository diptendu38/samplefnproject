from fdk import response
import io
import logging 
_response = {"status":"error"}

def handler(ctx, data: io.BytesIO = None):
    
    logging.getLogger().info("This is a test messege for debugging purpose")
    global _response
    
    name = "World"
    
    try:
        # Converting the input data from bytes to string format
        token = data.getvalue().decode('utf-8')
        logging.getLogger().info(token)
        _response = token
    # Handling any exceptions or errors during the execution
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))

    logging.getLogger().info("Inside Python Hello World function")
    
    
    return response.Response(
        ctx, _response          
    )
