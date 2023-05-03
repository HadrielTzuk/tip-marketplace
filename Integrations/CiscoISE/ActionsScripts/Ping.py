from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"CiscoISE"


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u"CiscoISE_Ping"
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)

    # Test regular API.
    result_value = cim.ping()
    
    if result_value:
        output_message = u'Connection Established.'
    else:
        output_message = u'Connection Failed.'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
