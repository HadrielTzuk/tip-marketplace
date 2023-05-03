from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, construct_csv
from QualysVMManager import QualysVMManager
from constants import INTEGRATION_NAME, LIST_GROUPS_SCRIPT_NAME
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_GROUPS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    json_results = {}

    try:
        qualys_manager = QualysVMManager(api_root, username, password, verify_ssl)
        groups = qualys_manager.list_asset_groups()

        if groups:
            json_results = json.dumps(groups)
            csv_output = construct_csv(groups)
            siemplify.result.add_data_table("Groups", csv_output)
            output_message = f"Successfully returned {len(groups)} groups from {INTEGRATION_NAME}."
            siemplify.result.add_result_json(json_results)
        else:
            output_message = f"No groups found in {INTEGRATION_NAME}."
            
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_GROUPS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_GROUPS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
