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

    siemplify.script_name = u"NGFW - Edit blocked application"

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

    app2BlockInput = extract_action_param(siemplify, param_name=u"Applications To Block", print_value=True,
                                          default_value=u"")
    app2UnBlockInput = extract_action_param(siemplify, param_name=u"Applications To UnBlock", print_value=True,
                                            default_value=u"")
    app2Block = set()
    app2UnBlock = set()
    json_results = []

    for app in app2BlockInput.split(u","):
        if app and (app not in app2Block):
            app2Block.add(app)

    for app in app2UnBlockInput.split(u","):
        if app and (app not in app2Block):
            app2UnBlock.add(app)

    if app2Block or app2UnBlock:
        api = NGFWManager(api_root, username, password, siemplify.run_folder, verify_ssl)
        api.EditBlockedApplication(deviceName=deviceName, vsysName=vsysName,
                                   policyName=policy_name,
                                   applicationsToAdd=app2Block,
                                   applicationsToRemove=app2UnBlock)

        json_results = api.FindRuleBlockedApplications(
            api.GetCurrenCanidateConfig(),
            deviceName, vsysName, policy_name
        )
        output_message = u'Following apps were affected:\n'

        if app2Block != set():
            output_message = output_message + u"Apps blocked: {0}\n".format(
                u','.join(app2Block))

        if app2UnBlock != set():
            output_message = output_message + u"Apps unblocked: {0}\n".format(
                u','.join(app2UnBlock))

        result_value = u'true'

    else:
        output_message = u'Nothing changed - no input'
        result_value = u'false'

    siemplify.result.add_result_json(json.dumps(list(json_results)))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
