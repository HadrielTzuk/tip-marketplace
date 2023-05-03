from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager
from TIPCommon import extract_configuration_param, extract_action_param
import json

INTEGRATION_NAME = u"PaloAltoNGFW"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - GetBlockedApplications"
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

    api = NGFWManager(api_root, username, password, siemplify.run_folder, verify_ssl=verify_ssl)
    config = api.GetCurrenCanidateConfig()
    currentApplications = api.FindRuleBlockedApplications(config=config,
                                                          deviceName=deviceName,
                                                          vsysName=vsysName,
                                                          policyName=policy_name)

    blockedApps = u", ".join(currentApplications)

    msg = u"Current Blocked applications for {0}->{1}->{2}:\n {3}".format(
        deviceName, vsysName, policy_name, u'\n'.join(blockedApps.split(u',')))

    output_message = msg

    siemplify.result.add_result_json(json.dumps(list(currentApplications)))
    siemplify.end(output_message, json.dumps(list(currentApplications)))


if __name__ == "__main__":
    main()
