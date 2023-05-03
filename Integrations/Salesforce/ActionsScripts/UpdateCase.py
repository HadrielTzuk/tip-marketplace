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

    case_number = siemplify.parameters.get('Case Number')
    subject = siemplify.parameters.get('Subject')
    status = siemplify.parameters.get('Status')
    description = siemplify.parameters.get('Description')
    origin = siemplify.parameters.get('Origin')
    priority = siemplify.parameters.get('Priority')
    case_type = siemplify.parameters.get('Type')

    case = salesforce_manager.get_case_by_number(case_number)

    salesforce_manager.update_case(
        case_id=case['Id'],
        subject=subject,
        status=status,
        description=description,
        origin=origin,
        priority=priority,
        case_type=case_type
    )

    output_message = "Successfully updated case {case_number}.".format(
        case_number=case_number
    )

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()
