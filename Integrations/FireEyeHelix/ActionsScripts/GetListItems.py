from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FireEyeHelixConstants import PROVIDER_NAME, GET_LIST_ITEMS_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from FireEyeHelixExceptions import FireEyeHelixNotFoundListException

TABLE_HEADER = "{} List Items"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_LIST_ITEMS_SCRIPT_NAME
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
    short_name = extract_action_param(siemplify, param_name='List Short Name', is_mandatory=True, print_value=True)
    value = extract_action_param(siemplify, param_name='Value', is_mandatory=False, print_value=True)
    item_type = extract_action_param(siemplify, param_name='Type', is_mandatory=False, print_value=True)
    sort_by = extract_action_param(siemplify, param_name='Sort By', is_mandatory=False, print_value=True)
    sort_order = extract_action_param(siemplify, param_name='Sort Order', is_mandatory=False, print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Items To Return',
                                 is_mandatory=False, input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        results = manager.get_list_items(
            short_name=short_name,
            value=value,
            item_type=item_type,
            sort_by=sort_by,
            sort_order=sort_order,
            limit=limit
        )

        if results:
            output_message = "Successfully returned items of the \"{}\" list from {}.".format(short_name, PROVIDER_NAME)
            siemplify.result.add_result_json([result.to_json() for result in results])
            siemplify.result.add_entity_table(
                TABLE_HEADER.format(PROVIDER_NAME),
                construct_csv([result.to_csv() for result in results])
            )
        else:
            msg = "No items were found in the list with short name \"{}\" in {}."
            output_message = msg.format(short_name, PROVIDER_NAME)
            result_value = False

    except FireEyeHelixNotFoundListException:
        output_message = "List with short name \"{}\" was not found in {}.".format(short_name, PROVIDER_NAME)
        result_value = False
    except Exception as e:
        output_message = "Error executing action \"Get List Items\". Reason: {}".format(e)
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
