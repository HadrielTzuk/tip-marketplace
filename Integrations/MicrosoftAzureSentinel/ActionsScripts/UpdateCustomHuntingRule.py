from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, PRODUCT_NAME, UPDATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from utils import string_to_multi_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME
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

    display_name = extract_action_param(siemplify, param_name='Display Name', print_value=True)

    query = extract_action_param(siemplify, param_name='Query', print_value=True)

    description = extract_action_param(siemplify, param_name='Description', print_value=True)

    tactics = string_to_multi_value(extract_action_param(siemplify, param_name='Tactics', print_value=True))

    hunting_rule_id = extract_action_param(siemplify, param_name='Hunting Rule ID', is_mandatory=True, print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'Failed to update hunting rule with ID {hunting_rule_id}'

    try:
        MicrosoftAzureSentinelManager.validate_tactics(tactics)

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

        custom_hunting_rule = manager.update_custom_hunting_rule(
            custom_hunting_rule_id=hunting_rule_id,
            display_name=display_name,
            query=query,
            description=description,
            tactics=tactics
        )

        if custom_hunting_rule:
            output_message = f'Successfully updated {PRODUCT_NAME} hunting rule with ID {custom_hunting_rule}'
            siemplify.result.add_result_json(custom_hunting_rule.to_json())

    except Exception as e:
        output_message = f"Error executing action '{UPDATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME}'. Reason: {e}"
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
