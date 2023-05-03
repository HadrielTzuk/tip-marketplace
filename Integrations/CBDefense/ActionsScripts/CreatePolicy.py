from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from CarbonBlackDefenseManager import CBDefenseManager
from TIPCommon import extract_configuration_param, extract_action_param
import json


INTEGRATION_NAME = "CBDefense"
SCRIPT_NAME = "Create Policy"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          is_mandatory=True)

    policy_name = extract_action_param(siemplify, param_name='Policy Name', print_value=True, is_mandatory=True)
    policy_desc = extract_action_param(siemplify, param_name='Policy Description', print_value=True, is_mandatory=True)
    priority = extract_action_param(siemplify, param_name='Priority Level', print_value=True, is_mandatory=True)
    policy_details = extract_action_param(siemplify, param_name='Policy Details', print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        try:
            policy_details = json.loads(policy_details)
        except Exception as e:
            raise Exception("Invalid json. Cannot create policy. Please try again. {0}".format(e))

        # If no exception occur - then connection is successful
        siemplify.LOGGER.info("Connecting to Carbon Black Defense.")
        cb_defense = CBDefenseManager(api_root, api_key)
        cb_defense.test_connectivity()

        siemplify.LOGGER.info("Creating new policy.")
        new_policy_id = cb_defense.create_new_policy(description=policy_desc, name=policy_name, priority_level=priority, policy_details=policy_details) or 0

        if new_policy_id:
            output_message = f'Carbon Black Defense - Policy {policy_name} created successfully. Policy ID: {new_policy_id}'

        else:
            output_message = 'Could not create new policy.'

        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(output_message)
        result_value = new_policy_id

    except Exception as e:
        siemplify.LOGGER.error("General error occurred while running action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = 0
        output_message = "An error occurred while running action. Error: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
