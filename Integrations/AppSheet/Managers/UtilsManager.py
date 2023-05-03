import requests

def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {str} Default message to display on error
    """
    
    try:
        response.json() # The product returns status code 200, but nothing in the response. If there is nothing in the response, an error related to the payload occured
    except Exception:
        raise Exception("Invalid payload was provided. Please check the spelling of Table Name and structure of the JSON object of the record")
    
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        raise Exception(
            '{error_msg}: {error} {text}'.format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )

    return True
