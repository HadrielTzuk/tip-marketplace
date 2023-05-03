from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoISEManager import CiscoISEManager
from SiemplifyDataModel import EntityTypes
import json
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"CiscoISE"


def convert_string_to_bool(value):
    """
    Convert bool string to bool value -> The user has t add a value to update that has to be passed as bool.
    :param value: {string}
    :return: {bool}
    """
    if value:
        if value.lower() == u'true':
            return True
        elif value.lower() == u'false':
            # Validate false input too.
            return False
        else:
            raise Exception(u'Parameter value has to be "True" or "False" string, added "{0}"'.format(value))


@output_handler
def main():
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u'CiscoISE_UpdateEndpoint'
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
    updated_addresses = []
    errors = []
    errors_flag = False

    # Parameters.
    description = extract_action_param(siemplify, param_name=u"Description", print_value=True)
    group_id = extract_action_param(siemplify, param_name=u"Group ID", print_value=True)
    portal_user = extract_action_param(siemplify, param_name=u"Portal User", print_value=True)
    identity_store = extract_action_param(siemplify, param_name=u"Identity Store", print_value=True)
    identity_store_id = extract_action_param(siemplify, param_name=u"Identity Store ID", print_value=True)

    try:
        # Cistom attributes must be a dict.
        custom_attributes = extract_action_param(siemplify, param_name=u"Custom Attributes", print_value=True)
        if custom_attributes:
            custom_attributes = json.loads(custom_attributes)
    except Exception as err:
        siemplify.LOGGER.error(u'Error fetching custom attributes, input not in corrent format(Must be dict), ERROR: {0}'.format(err.message))
        siemplify.LOGGER.exception(err)
        raise Exception(u'Error fetching custom attributes, input not in corrent format(Must be dict), ERROR: {0}'.format(err.message))

    mdm_server_name = extract_action_param(siemplify, param_name=u"MDM Server Name", print_value=True)
    mdm_os = extract_action_param(siemplify, param_name=u"MDM OS", print_value=True)
    mdm_manufacturer = extract_action_param(siemplify, param_name=u"MDM Manufacturer", print_value=True)
    mdm_model = extract_action_param(siemplify, param_name=u"MDM Model", print_value=True)
    mdm_imei = extract_action_param(siemplify, param_name=u"MDM IMEI", print_value=True)
    mdm_phone_number = extract_action_param(siemplify, param_name=u"MDM Phone Number", print_value=True)

    # Bool Params.
    mdm_encrypted = extract_action_param(siemplify, param_name=u"MDM Encrypted", print_value=True, input_type=bool)
    mdm_pinlock = extract_action_param(siemplify, param_name=u"MDM Pinlock", print_value=True, input_type=bool)
    mdm_jail_broken = extract_action_param(siemplify, param_name=u"MDM Jail Broken", print_value=True, input_type=bool)
    mdm_reachable = extract_action_param(siemplify, param_name=u"MDM Reachable", print_value=True, input_type=bool)
    mdm_enrolled = extract_action_param(siemplify, param_name=u"MDM Enrolled", print_value=True, input_type=bool)
    mdm_compliance_status = extract_action_param(siemplify, param_name=u"MDM Compliance Status", print_value=True,
                                                 input_type=bool)

    ip_addresses_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    for entity in ip_addresses_entities:
        # Fetch MAC address
        try:
            mac_address = cim.get_endpoint_mac_by_ip(entity.identifier)
            cim.update_endpoint(mac_address, description=description, group_id=group_id, portal_user=portal_user,
                                identity_store=identity_store, identity_store_id=identity_store_id,
                                custom_attributes=custom_attributes, mdm_server_name=mdm_server_name,
                                mdm_reachable=mdm_reachable, mdm_enrolled=mdm_enrolled,
                                mdm_compliance_status=mdm_compliance_status, mdm_os=mdm_os, mdm_manufacturer=mdm_manufacturer,
                                mdm_model=mdm_model, mdm_encrypted=mdm_encrypted, mdm_pinlock=mdm_pinlock,
                                mdm_jail_broken=mdm_jail_broken, mdm_imei=mdm_imei, mdm_phone_number=mdm_phone_number)
            updated_addresses.append(entity.identifier)
        except Exception as err:
            siemplify.LOGGER.error(u'Error updating "{0}", ERROR: {1}'.format(entity.identifier, err.message))
            errors.append(u'Error updating "{0}", ERROR: {1}'.format(entity.identifier, err.message))
            errors_flag = True
            siemplify.LOGGER.exception(err)

    if updated_addresses:
        output_message = u"Following endpoints were updated: {0}".format(u",".join(updated_addresses))
        result_value = True
    else:
        output_message = u"No endpoints were updated."

    if errors_flag:
        output_message = u"{0} \n \n ERRORS:{1}".format(output_message, u" \n ".join(errors))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
