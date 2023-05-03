from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SalesforceManager import SalesforceManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    configurations = siemplify.get_configuration('Salesforce')
    server_addr = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']
    token = configurations['Token']
    verify_ssl = configurations.get('Verify SSL', 'False').lower() == 'true'

    salesforce_manager = SalesforceManager(username, password, token,
                                           server_addr=server_addr,
                                           verify_ssl=verify_ssl)

    salesforce_manager.test_connectivity()

    output_message = "Successfully connected."

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()