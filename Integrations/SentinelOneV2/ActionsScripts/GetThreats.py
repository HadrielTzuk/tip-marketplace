from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SentinelOneV2Manager import DEFAULT_THREATS_LIMIT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, PRODUCT_NAME, THREATS_TABLE_NAME, GET_THREATS_SCRIPT_NAME
from utils import string_to_multi_value
from SentinelOneV2Factory import SentinelOneV2ManagerFactory, API_VERSION_2_0


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_THREATS_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    mitigation_statuses = string_to_multi_value(extract_action_param(siemplify, param_name='Mitigation Status',
                                                                     print_value=True))
    created_until = extract_action_param(siemplify, param_name='Created until', print_value=True)
    api_version = extract_action_param(siemplify, param_name='API Version', default_value=API_VERSION_2_0)
    created_from = extract_action_param(siemplify, param_name='Created from', print_value=True)
    resolved_threats = extract_action_param(siemplify, param_name='Resolved Threats', input_type=bool, print_value=True)
    threat_display_name = extract_action_param(siemplify, param_name='Threat Display Name', print_value=True)
    limit = extract_action_param(siemplify, param_name='Limit', default_value=DEFAULT_THREATS_LIMIT, input_type=int,
                                 print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    json_results, table_results = [], []
    result_value = True

    try:
        manager = SentinelOneV2ManagerFactory(api_version).get_manager(api_root=api_root, api_token=api_token,
                                                                       verify_ssl=verify_ssl,
                                                                       force_check_connectivity=True)

        for threat in manager.get_threats(mitigation_statuses=mitigation_statuses, resolved_threats=resolved_threats,
                                          created_until=created_until, limit=limit, created_from=created_from,
                                          display_name=threat_display_name):
            json_results.append(threat.to_json())
            table_results.append(threat.to_csv())

        if json_results:
            siemplify.result.add_data_table(THREATS_TABLE_NAME, construct_csv(table_results))
            siemplify.result.add_result_json(json_results)
            output_message = 'Successfully retrieved information about the available threats in {}.'\
                .format(PRODUCT_NAME)
        else:
            result_value = False
            output_message = 'No information about threats was found based on the provided criteria.'

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_THREATS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
