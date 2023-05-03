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
    siemplify.script_name = u'CiscoISE_Unquarantine Address'
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             input_type=bool, print_value=True)

    cim = CiscoISEManager(api_root, username, password, verify_ssl)


    # Variables.
    unquarantined_ips = []
    result_value = False
    errors = []
    errors_flag = False

    ip_addresses = [entity.identifier for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    for ip_address in ip_addresses:
        try:
            mac_address = cim.get_endpoint_mac_by_ip(ip_address)
            cim.unquarantine_endpoint(mac_address)
            unquarantined_ips.append(ip_address)
        except Exception as err:
            siemplify.LOGGER.error(u'Error unquarantine "{0}", ERROR: {1}'.format(ip_address, err.message))
            errors_flag = True
            errors.append(u'Error unquarantine "{0}", ERROR: {1}'.format(ip_address, err.message))

    if unquarantined_ips:
        output_message = u"{0} were unquarantined.".format(u",".join(unquarantined_ips))
        result_value = True
    else:
        output_message = u"No addresses were unquarantined."

    if errors_flag:
        output_message = u"{0} \n \n  ERRORS: {1}".format(output_message, errors)
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
