from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    LIST_CUSTOM_HUNTING_RULES_SCRIPT_NAME,
    HUNTING_RULES_TABLE_NAME
)
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from utils import string_to_multi_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_CUSTOM_HUNTING_RULES_SCRIPT_NAME
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

    names = string_to_multi_value(extract_action_param(siemplify, param_name='Hunting Rule Names to Return',
                                                       print_value=True))
    tactics = string_to_multi_value(extract_action_param(siemplify, param_name='Fetch Specific Hunting Rule Tactics',
                                                         print_value=True))
    limit = extract_action_param(siemplify, param_name='Max rules to return', print_value=True, input_type=int)
    limit = limit if limit and limit > 0 else None

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'No {PRODUCT_NAME} hunting rules were found'

    try:
        MicrosoftAzureSentinelManager.validate_tactics(tactics)

        sentinel_manager = MicrosoftAzureSentinelManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            resource=resource,
            subscription_id=subscription_id,
            login_url=login_url,
            verify_ssl=verify_ssl)

        custom_hunting_rules = sentinel_manager.get_custom_hunting_rules(names=names, tactics=tactics, limit=limit)

        if custom_hunting_rules:
            output_message = f'Successfully returned {PRODUCT_NAME} hunting rules'

            siemplify.result.add_result_json([custom_hunting_rule.to_json()
                                              for custom_hunting_rule in custom_hunting_rules])

            siemplify.result.add_data_table(
                HUNTING_RULES_TABLE_NAME,
                construct_csv([custom_hunting_rule.to_csv() for custom_hunting_rule in custom_hunting_rules])
            )

    except Exception as e:
        output_message = f"Error executing action '{LIST_CUSTOM_HUNTING_RULES_SCRIPT_NAME}'. Reason: {e}"
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
