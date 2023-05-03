from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from SumoLogicCloudSIEMManager import SumoLogicCloudSIEMManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ADD_COMMENT_TO_INSIGHT_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_INSIGHT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    access_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access ID",
                                            print_value=True)
    access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # action parameters
    insight_id = extract_action_param(siemplify, param_name="Insight ID", is_mandatory=True, print_value=True)
    comment = extract_action_param(siemplify, param_name="Comment", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = SumoLogicCloudSIEMManager(api_root=api_root, api_key=api_key, access_id=access_id,
                                            access_key=access_key, verify_ssl=verify_ssl,
                                            siemplify_logger=siemplify.LOGGER)

        json_response = manager.add_comment_to_insight(insight_id=insight_id, comment=comment)

        siemplify.result.add_result_json(json_response)
        output_message = f"Successfully added a comment to an insight with ID \"{insight_id}\" in Sumo Logic Cloud SIEM."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ADD_COMMENT_TO_INSIGHT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action {ADD_COMMENT_TO_INSIGHT_SCRIPT_NAME}. Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
