from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FireEyeHelixConstants import PROVIDER_NAME, GET_LISTS_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

TABLE_HEADER = "FireEye Helix Lists"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_LISTS_SCRIPT_NAME
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
    name = extract_action_param(siemplify, param_name='Name', is_mandatory=False, print_value=True)
    short_name = extract_action_param(siemplify, param_name='Short Name', is_mandatory=False, print_value=True)
    active = extract_action_param(siemplify, param_name='Active', is_mandatory=False, input_type=bool, print_value=True)
    internal = extract_action_param(siemplify, param_name='Internal', is_mandatory=False,
                                    input_type=bool, print_value=True)
    protected = extract_action_param(siemplify, param_name='Protected', is_mandatory=False,
                                     input_type=bool, print_value=True)
    sort_by = extract_action_param(siemplify, param_name='Sort By', is_mandatory=False, print_value=True)
    sort_order = extract_action_param(siemplify, param_name='Sort Order', is_mandatory=False, print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Lists To Return', is_mandatory=False,
                                 input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        results = manager.get_lists(
            name=name,
            short_name=short_name,
            active=active,
            internal=internal,
            protected=protected,
            sort_by=sort_by,
            sort_order=sort_order,
            limit=limit
        )

        if results:
            output_message = "Successfully returned lists from FireEye Helix."
            siemplify.result.add_result_json([result.to_json() for result in results])
            siemplify.result.add_entity_table(
                TABLE_HEADER,
                construct_csv([result.to_csv() for result in results])
            )
        else:
            output_message = "No lists were found that match the set criteria."
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Get Lists\". Reason: {}".format(e)
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
