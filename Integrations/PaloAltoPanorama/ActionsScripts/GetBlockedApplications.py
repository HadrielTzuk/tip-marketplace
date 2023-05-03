from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from TIPCommon import extract_configuration_param, extract_action_param
import json

SCRIPT_NAME = u"Panorama - GetBlockedApplications"
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

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    api = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)
    config = api.GetCurrenCanidateConfig()

    siemplify.LOGGER.info(u"Fetching blocked applications from {}".format(PROVIDER_NAME))
    currentApplications = api.FindRuleBlockedApplications(config=config,
                                                          deviceName=deviceName,
                                                          deviceGroupName=device_group_name,
                                                          policyName=policy_name)
    siemplify.LOGGER.info(u"Successfully fetched blocked applications from {}".format(PROVIDER_NAME))

    blockedApps = ", ".join(currentApplications)

    output_message = u"Successfully listed blocked applications in the policy \"{}:\n {}".format(policy_name, u'\n'.
                                                                                      join(blockedApps.split(u',')))

    siemplify.result.add_result_json(json.dumps(list(currentApplications)))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, json.dumps(list(currentApplications)))


if __name__ == "__main__":
    main()
