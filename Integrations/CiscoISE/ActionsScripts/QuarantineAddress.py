from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"CiscoISE"


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u'CiscoISE_Quarantine Address'

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)

    # Variables.
    quarantined_ips = []
    result_value = False
    errors_flag = False
    errors = []

    ip_addresses = [entity.identifier for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    # Parameters.
    policy_name = extract_action_param(siemplify, param_name=u"Policy Name", print_value=True)

    for ip_address in ip_addresses:
        try:
            mac_address = cim.get_endpoint_mac_by_ip(ip_address)
            cim.quarantine_endpoint(mac_address, policy_name)
            quarantined_ips.append(ip_address)
        except Exception as err:
            siemplify.LOGGER.error(u'Error quarantine "{0}", ERROR: {1}'.format(ip_address, err.message))
            errors.append(u'Error quarantine "{0}", ERROR: {1}'.format(ip_address, err.message))
            errors_flag = True

    if quarantined_ips:
        output_message = u"{0} were quarantined.".format(u",".join(quarantined_ips))
        result_value = True
    else:
        output_message = u"No addresses were quarantined."

    if errors_flag:
        output_message = u"{0}, ERRORS: {1}".format(output_message, u" \n ".join(errors))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
