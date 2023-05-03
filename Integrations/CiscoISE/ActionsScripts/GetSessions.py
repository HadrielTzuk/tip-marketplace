from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from TIPCommon import dict_to_flat, construct_csv, extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"CiscoISE"
TABLE_HEADER = u'Sessions'


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u"CiscoISE_GetSessions"
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)

    # Variables.
    result_value = False

    session_list = cim.get_sessions()
    if session_list:
        csv = construct_csv(map(dict_to_flat, session_list))
        siemplify.result.add_data_table(TABLE_HEADER, csv)
        result_value = True
        output_message = u'Found "{0}" active sessions.'.format(len(session_list))
    else:
        output_message = u"No active sessions found."
        
    siemplify.end(output_message, result_value)
    
    
if __name__ == "__main__":
    main()
