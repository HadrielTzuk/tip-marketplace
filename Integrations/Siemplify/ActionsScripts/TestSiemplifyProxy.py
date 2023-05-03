from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
import requests
import urllib


ACTION_NAME = 'TestSiemplifyProxy'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    # Parameters.
    url = siemplify.parameters.get('Endpoint URL')
    method = siemplify.parameters.get('HTTP Method')
    body = siemplify.parameters.get("Body")

    verify_ssl = str(siemplify.parameters.get("Verify SSL", "False")).lower() == 'true'

    siemplify.LOGGER.info("Current proxy configuration: {}", urllib.getproxies())

    session = requests.Session()
    session.verify = verify_ssl

    is_success = False

    try:
        response = session.request(method.upper(), url, data=body)
        response.raise_for_status()
        is_success = True
        output_message = "Successfully connected to {}".format(url)
    except requests.exceptions.SSLError as e:
        output_message = "Couldn't establish secure connection with {}. Error: {}".format(url, e.message)
    except requests.exceptions.ConnectionError as e:
        output_message = "Couldn't establish connection with {}".format(url)
    except requests.exceptions.HTTPError as e:
        output_message = "Unable to connect to {} due to client/server error. Error: {}".format(url, e.message)
    except Exception as e:
        output_message = "Unable to connect to {} due to an unknown reason. Error: {}".format(url, e)
    finally:
        if not is_success:
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(e)

    siemplify.end(output_message, is_success)


if __name__ == '__main__':
    main()
