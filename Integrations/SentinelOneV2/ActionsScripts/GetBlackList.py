from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, GET_BLACK_LIST_SCRIPT_NAME, DEFAULT_BLACK_LIST_LIMIT, MAX_BLACK_LIST_LIMIT, \
    PRODUCT_NAME, BLACKLIST_HASHES_TABLE_NAME
from exceptions import SentinelOneV2ValidationError, SentinelOneV2PermissionError
from utils import string_to_multi_value
from SentinelOneV2Factory import SentinelOneV2ManagerFactory



@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_BLACK_LIST_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    hashes = string_to_multi_value(extract_action_param(siemplify, param_name='Hash', print_value=True))
    site_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Site IDs', print_value=True))
    group_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Group IDs', print_value=True))
    account_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Account IDs', print_value=True))
    limit = extract_action_param(siemplify, param_name='Limit', input_type=int,
                                 print_value=True)
    limit = limit and max(0, min(limit, MAX_BLACK_LIST_LIMIT)) or None
    query = extract_action_param(siemplify, param_name='Query', print_value=True)
    use_global_blacklist = extract_action_param(siemplify, param_name='Use Global Blacklist', input_type=bool,
                                                print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = "Successfully retrieved blacklisted hashes based on the provided filter criteria in {}."\
        .format(PRODUCT_NAME)
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    results = []

    try:
        if not site_ids and not group_ids and not account_ids and not use_global_blacklist:
            raise SentinelOneV2ValidationError(
                "at least one value should be provided for \"Site IDs\" or \"Group IDs\" or \"Account IDs\" parameters "
                "or \"Use Global Blacklist\" should be enabled.")

        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl, force_check_connectivity=True)
        if not hashes:
            results = manager.get_blacklist_items(hash_value=hashes, site_ids=site_ids, group_ids=group_ids,
                                                  account_ids=account_ids, limit=limit, query=query,
                                                  tenant=use_global_blacklist)
        else:
            for hash_value in hashes:
                try:
                    results.extend(manager.get_blacklist_items(hash_value=hash_value, site_ids=site_ids,
                                                               group_ids=group_ids, account_ids=account_ids,
                                                               limit=limit, query=query, tenant=use_global_blacklist))
                except Exception as err:
                    if isinstance(err, SentinelOneV2PermissionError):
                        raise
                    siemplify.LOGGER.error("An error occurred on hash: {}".format(hash_value))
                    siemplify.LOGGER.exception(err)
        if results:
            siemplify.result.add_result_json([threat.to_json() for threat in results])
            siemplify.result.add_data_table(BLACKLIST_HASHES_TABLE_NAME,
                                            construct_csv([threat.to_csv() for threat in results]))
        else:
            output_message = 'No blacklisted hashes were found for the provided criteria in {}.'.format(PRODUCT_NAME)
            result_value = False

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(GET_BLACK_LIST_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
