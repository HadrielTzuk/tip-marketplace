from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
import requests
from urlparse import urlparse


ACTION_NAME = 'SiemplifyTest - HTTP Custom Proxy'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    # Parameters.
    url = siemplify.parameters.get('Endpoint URL')
    method = siemplify.parameters.get('HTTP Method')
    body = siemplify.parameters.get("Body")

    proxy_server_address = siemplify.parameters.get('Proxy Server Address')
    proxy_username = siemplify.parameters.get('Proxy Username')
    proxy_password = siemplify.parameters.get('Proxy Password')

    verify_ssl = str(siemplify.parameters.get("Verify SSL", "False")).lower() == 'true'

    session = requests.Session()
    session.trust_env = False
    session.verify = verify_ssl

    server_url = urlparse(proxy_server_address)

    scheme = server_url.scheme
    hostname = server_url.hostname
    port = server_url.port

    credentials = ""

    if proxy_username and proxy_password:
        credentials = "{0}:{1}@".format(proxy_username, proxy_password)

    proxy_str = "{0}://{1}{2}".format(scheme, credentials, hostname)

    if port:
        proxy_str += ":{0}".format(str(port))

    proxies = {
        "http": proxy_str,
        "https": proxy_str
    }

    response = session.request(method.upper(), url, proxies=proxies, data=body)

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
