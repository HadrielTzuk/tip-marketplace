from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CarbonBlackDefenseManager import CBDefenseManager
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = "CBDefense"
SCRIPT_NAME = "Delete Policy"


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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # If no exception occur - then connection is successful
        siemplify.LOGGER.info("Connecting to Carbon Black Defense.")
        cb_defense = CBDefenseManager(api_root, api_key)
        cb_defense.test_connectivity()

        siemplify.LOGGER.info(f"Deleting policy {policy_name}.")
        is_success_delete_policy = cb_defense.delete_policy(policy_name)

        if is_success_delete_policy:
            output_message = f'Carbon Black Defense - {policy_name} deleted successfully.'

        else:
            output_message = f'Could not delete {policy_name}.'

        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(output_message)
        result_value = "true"

    except Exception as e:
        siemplify.LOGGER.error("General error occurred while running action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "An error occurred while running action. Error: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
