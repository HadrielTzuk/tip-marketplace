from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager, NGFWException
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = u"PaloAltoNGFW"
SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - BlockIpsInPolicy"

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    deviceName = extract_action_param(siemplify, param_name=u"Device Name", print_value=True, is_mandatory=True)
    vsysName = extract_action_param(siemplify, param_name=u"Vsys Name", print_value=True, is_mandatory=True)
    policy_name = extract_action_param(siemplify, param_name=u"Policy Name", print_value=True, is_mandatory=True)
    target = extract_action_param(siemplify, param_name=u"Target", print_value=True, is_mandatory=True)

    suitable_entity_identifiers = [entity.identifier for entity in siemplify.target_entities
                                   if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    successful_entities, failed_entities, existing_entities = [], [], []
    json_results = {"success": [], "failure": [], "already_exist": []}
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        if not target != u'source' and not target != u'destination':
            raise NGFWException(u"Target must be source or destination!")

        if suitable_entity_identifiers:
            api = NGFWManager(api_root, username, password, siemplify.run_folder, verify_ssl=verify_ssl)
            existing_ips = api.FindRuleBlockedIps(deviceName, vsysName, policy_name, target) or []
            for entity_identifier in suitable_entity_identifiers:
                if entity_identifier in existing_ips:
                    existing_entities.append(entity_identifier)
                else:
                    try:
                        api.EditBlockedIps(deviceName=deviceName, vsysName=vsysName,
                                           policyName=policy_name, target=target,
                                           IpsToAdd=[entity_identifier])
                        successful_entities.append(entity_identifier)
                    except Exception as err:
                        siemplify.LOGGER.error(u"Some errors occurred '{}'".format(err))
                        siemplify.LOGGER.exception(err)
                        failed_entities.append(entity_identifier)

            if successful_entities:
                output_message = u"Successfully blocked the following IP addresses in Palo Alto NGFW: " \
                                 u"{} \n".format(u', '.join(successful_entities))

                if failed_entities:
                    output_message += u"Action wasn't able to block the following IP addresses in Palo Alto NGFW: " \
                                      u"{}\n".format(u', '.join(failed_entities))
            else:
                output_message = u"No IP addresses were blocked in Palo Alto NGFW.\n"
                result_value = False

            if existing_entities:
                result_value = True
                output_message += u"The following IP addresses were already blocked in Palo Alto NGFW: " \
                                  u"{}\n".format(u', '.join(existing_entities))

            json_results['success'] = successful_entities
            json_results['failure'] = failed_entities
            json_results['already_exist'] = existing_entities

            siemplify.result.add_result_json(json_results)

        else:
            output_message = u"No suitable entities found in the scope."
            result_value = False

    except Exception as e:
        output_message = u'Error executing action \"Block Ips In Policy\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
