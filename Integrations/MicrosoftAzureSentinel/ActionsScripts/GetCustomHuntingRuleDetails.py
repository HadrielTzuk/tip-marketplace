from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, flat_dict_to_csv
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    GET_CUSTOM_HUNTING_RULE_DETAILS_SCRIPT_NAME,
    CUSTOM_HUNTING_RULE_DETAILS_TABLE_NAME
)
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_CUSTOM_HUNTING_RULE_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

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

    hunting_rule_id = extract_action_param(siemplify, param_name='Hunting Rule ID', is_mandatory=True, print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'No hunting rule with id {hunting_rule_id} was found'

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

        custom_hunting_rule = manager.get_custom_hunting_rule(custom_hunting_rule_id=hunting_rule_id)

        if custom_hunting_rule:
            siemplify.result.add_result_json(custom_hunting_rule.to_json())

            siemplify.result.add_data_table(
                title=CUSTOM_HUNTING_RULE_DETAILS_TABLE_NAME,
                data_table=custom_hunting_rule.to_table()
            )
            output_message = f'Successfully returned {PRODUCT_NAME} hunting rule {hunting_rule_id} details'

    except Exception as e:
        output_message = f"Error executing action '{GET_CUSTOM_HUNTING_RULE_DETAILS_SCRIPT_NAME}'. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
