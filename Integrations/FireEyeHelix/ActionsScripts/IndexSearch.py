from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FireEyeHelixConstants import PROVIDER_NAME, INDEX_SEARCH_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = INDEX_SEARCH_SCRIPT_NAME
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Init Integration Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Root",
        is_mandatory=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Token",
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool
    )

    # Init Action Parameters
    query = extract_action_param(siemplify, param_name='Query', is_mandatory=True, print_value=True)
    time_frame = extract_action_param(siemplify, param_name='Time Frame', is_mandatory=False, print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Results To Return', is_mandatory=False,
                                 input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        result = manager.index_search(
            query=query,
            time_frame=time_frame,
            limit=limit
        )

        if result.contains_results():
            siemplify.result.add_result_json(result.to_json())
            output_message = "Successfully returned results for the query \"{}\" in {}.".format(query, PROVIDER_NAME)
        else:
            output_message = "No results were found for the query \"{}\".".format(query)
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Index Search\". Reason: {}".format(e)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
