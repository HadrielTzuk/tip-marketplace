from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoFirepowerManager import CiscoFirepowerManager

INTEGRATION_PROVIDER = 'CiscoFirepowerManagementCenter'


@output_handler
def main():

    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(INTEGRATION_PROVIDER)
    verify_ssl = str(conf.get('Verify SSL', 'false').lower()) == str(True).lower()

    cisco_firepower_manager = CiscoFirepowerManager(conf['API Root'],
                                                    conf['Username'],
                                                    conf['Password'],
                                                    verify_ssl)

    # Invoke connection function.
    result_value = cisco_firepower_manager.get_domain_uuid_and_update_headers()

    if result_value:
        output_message = 'Connection Established.'
    else:
        output_message = 'Connection Failed.'

    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
