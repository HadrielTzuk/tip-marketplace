from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
from MicrosoftAzureSentinelManager import (
    MicrosoftAzureSentinelManager,
    DEFAULT_TIME_FRAME
)
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    GET_INCIDENT_STATISTICS_SCRIPT_NAME,
    INCIDENT_STATISTICS_BY_SEVERITY_TABLE_NAME,
    INCIDENT_STATISTICS_BY_STATUS_TABLE_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_INCIDENT_STATISTICS_SCRIPT_NAME
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

    time_frame = extract_action_param(siemplify, param_name='Time Frame', print_value=True, input_type=int,
                                      default_value=DEFAULT_TIME_FRAME)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'Successfully returned {PRODUCT_NAME} incident statistics'

    try:
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
        incident_statistic = manager.get_incident_statistics(time_frame=time_frame)

        siemplify.result.add_result_json(incident_statistic.to_json())

        if incident_statistic.has_properties:
            siemplify.result.add_data_table(
                title=INCIDENT_STATISTICS_BY_SEVERITY_TABLE_NAME,
                data_table=flat_dict_to_csv(incident_statistic.properties.aggregation_by_severity.to_csv()))

            siemplify.result.add_data_table(
                title=INCIDENT_STATISTICS_BY_STATUS_TABLE_NAME,
                data_table=flat_dict_to_csv(incident_statistic.properties.aggregation_by_status.to_csv()))

    except Exception as e:
        output_message = f"Error executing action '{GET_INCIDENT_STATISTICS_SCRIPT_NAME}'. Reason: {e}"
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
