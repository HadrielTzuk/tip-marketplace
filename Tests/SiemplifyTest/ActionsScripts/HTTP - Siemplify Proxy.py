from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
import requests
import urllib


ACTION_NAME = 'SiemplifyTest - HTTP Siemplify Proxy'


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

    response = session.request(method.upper(), url, data=body)

    try:
        response.raise_for_status()
    except Exception as e:
        siemplify.LOGGER.error("Unable to connect to {}".format(url))
        siemplify.LOGGER.exception(e)
        raise

    output_message = "Successfully connected to {}".format(url)
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
