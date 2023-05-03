from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SalesforceManager import SalesforceManager
import json


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

    case_number = siemplify.parameters.get('Case Number')

    case = salesforce_manager.get_case_by_number(case_number)

    siemplify.result.add_json("Case {}".format(case_number), json.dumps(case))

    output_message = "Successfully fetched case {case_number}.".format(
        case_number=case_number
    )

    siemplify.result.add_result_json(case)
    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
