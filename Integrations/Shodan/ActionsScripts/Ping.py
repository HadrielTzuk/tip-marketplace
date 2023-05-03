from SiemplifyUtils import output_handler
from ShodanManager import ShodanManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()

    conf = siemplify.get_configuration('Shodan')
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    api_key = conf.get('API key', "")
    shodan = ShodanManager(api_key, verify_ssl=verify_ssl)

    shodan.test_connectivity()

    output_message = "Connection Established"
    result_value = 'true'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
