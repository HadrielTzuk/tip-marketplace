from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    RUN_CUSTOM_HUNTING_RULE_SCRIPT_NAME,
    HUNTING_RULE_RESULTS_TABLE_NAME
)
from MicrosoftAzureSentinelManagerV2 import MicrosoftAzureSentinelManagerV2


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_CUSTOM_HUNTING_RULE_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root')

    login_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name='OAUTH2 Login Endpoint Url')
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID')

    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret')

    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name='Azure Active Directory ID')
    workspace_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                               param_name='Azure Sentinel Workspace Name')
    resource = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Azure Resource Group')

    subscription_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name='Azure Subscription ID')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, default_value=False)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    hunting_rule_id = extract_action_param(siemplify, param_name='Hunting Rule ID', is_mandatory=True, print_value=True)

    timeout = extract_action_param(siemplify, param_name='Timeout', print_value=True, input_type=int)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = 'Hunting rule executed successfully, but did not return any results.'

    try:
        manager = MicrosoftAzureSentinelManagerV2(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            resource=resource,
            subscription_id=subscription_id,
            login_url=login_url,
            verify_ssl=verify_ssl
        )

        query_result = manager.run_custom_hunting_rule(
            custom_hunting_rule_id=hunting_rule_id,
            timeout=timeout
        )

        if not query_result.is_empty():
            output_message = 'Hunting rule executed successfully'
            siemplify.result.add_result_json(query_result.to_json())

            siemplify.result.add_data_table(
                title=HUNTING_RULE_RESULTS_TABLE_NAME,
                data_table=construct_csv(query_result.to_table()))

    except Exception as e:
        output_message = f"Error executing action '{RUN_CUSTOM_HUNTING_RULE_SCRIPT_NAME}'. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
