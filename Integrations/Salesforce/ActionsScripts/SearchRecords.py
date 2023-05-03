from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv
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

    query = siemplify.parameters.get('Query')

    records = salesforce_manager.search(query)

    for key, results in records.items():
        csv_output = construct_csv(results)
        siemplify.result.add_data_table(key, csv_output)

    siemplify.result.add_result_json(records)
    siemplify.end("Search completed.", 'true')


if __name__ == '__main__':
    main()