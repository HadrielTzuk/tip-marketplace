from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager, PanoramaException
from TIPCommon import extract_configuration_param, extract_action_param
import json

SCRIPT_NAME = u"Panorama - UnblockIPsInPolicy"
PROVIDER_NAME = u"Panorama"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # Configuration.
    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Api Root")
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username")
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool)

    # Parameters
    deviceName = extract_action_param(siemplify, param_name=u"Device Name", is_mandatory=True, print_value=True)
    device_group_name = extract_action_param(siemplify, param_name=u"Device Group Name", is_mandatory=True,
                                             print_value=True)
    policy_name = extract_action_param(siemplify, param_name=u"Policy Name", is_mandatory=True, print_value=True)
    target = extract_action_param(siemplify, param_name=u"Target", is_mandatory=True, print_value=True)

    if not target != 'source' and not target != 'destination':
        raise PanoramaException("Target must be source or destination!")

    ipToUnBlock = set()
    json_results = []
    result_value = u'true'
    output_message = u""
    successful_entities = []
    failed_entities = []

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            ipToUnBlock.add(entity.identifier)

    if ipToUnBlock:
        api = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)
        for ip in ipToUnBlock:
            siemplify.LOGGER.info(u"Process entity: {} Started".format(ip))
            try:
                api.EditBlockedIps(deviceName=deviceName, deviceGroupName=device_group_name, policyName=policy_name,
                                   target=target, IpsToRemove=[ip])
                successful_entities.append(ip)
                siemplify.LOGGER.info(u"Successfully unblocked entity: {} from {}".format(ip, policy_name))
            except Exception as error:
                failed_entities.append(ip)
                siemplify.LOGGER.error(u"Unable to unblock entity: {}. Reason is: {}".format(ip, error))

        json_results = api.FindRuleBlockedIps(deviceName, device_group_name, policy_name, target)

        if successful_entities:
            output_message += (u'Successfully unblocked the following IPs in the Palo Alto Panorama policy \"{}\": '
                               u'{}'.format(policy_name, u"\n".join([entity for entity in successful_entities])))

        if failed_entities:
            output_message += u"\n\nAction was not able to unblock the following IPs in the Palo Alto Panorama " \
                              u"policy \"{}\": {}".format(policy_name, u"\n".join([entity for entity in
                                                                                   failed_entities]))

        if not successful_entities:
            output_message = u"No IPs were unblocked in the Palo Alto Panorama policy \"{}\"".format(policy_name)
            siemplify.LOGGER.info(output_message)
            result_value = u'false'

    else:
        output_message = u"No IPs found"
        result_value = u'false'

    siemplify.result.add_result_json(json.dumps(list(json_results)))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
