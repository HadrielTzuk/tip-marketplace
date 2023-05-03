from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    RUN_KQL_QUERY_SCRIPT_NAME,
    KQL_QUERY_RESULTS
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_KQL_QUERY_SCRIPT_NAME
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

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    query = extract_action_param(siemplify, param_name='KQL Query', is_mandatory=True, print_value=True)
    timespan = extract_action_param(siemplify, param_name='Time Span', print_value=True)
    timeout = extract_action_param(siemplify, param_name='Query Timeout', print_value=True, input_type=int)
    limit = extract_action_param(siemplify, param_name='Record Limit', print_value=True, input_type=int)
    limit = limit if limit and limit > 0 else None

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = 'Query executed successfully, but did not return any results.'

    try:
        MicrosoftAzureSentinelManager.validate_iso8601_duration(timespan)

        manager = MicrosoftAzureSentinelManager(
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

        query_result = manager.run_kql_query(
            query=query,
            timespan=timespan,
            timeout=timeout,
            limit=limit
        )

        if query_result and not query_result.is_empty():
            output_message = 'Query executed successfully'
            siemplify.result.add_result_json(query_result.to_json())

            siemplify.result.add_data_table(
                title=KQL_QUERY_RESULTS,
                data_table=construct_csv(query_result.to_table(include_empty_tactics=True)))

    except Exception as e:
        output_message = f"Error executing action '{RUN_KQL_QUERY_SCRIPT_NAME}'. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
