from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"CiscoISE"


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u'CiscoISE_Terminate Session'

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)

    # Parameters.
    node_server_name = extract_action_param(siemplify, param_name=u"Node Server Name", print_value=True)
    calling_station_id = extract_action_param(siemplify, param_name=u"Calling Station ID", print_value=True)
    terminate_type = extract_action_param(siemplify, param_name=u"Terminate Type", print_value=True, input_type=int,
                                          default_value=0)

    result_value = cim.terminate_session(node_server_name, calling_station_id, terminate_type)

    if result_value:
        output_message = u"Session terminated."
    else:
        output_message = u"Session was not terminated."

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
