from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, PRODUCT_NAME, CREATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME
from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from utils import string_to_multi_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME
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

    display_name = extract_action_param(siemplify, param_name='Display Name', is_mandatory=True, print_value=True)

    query = extract_action_param(siemplify, param_name='Query', is_mandatory=True, print_value=True)

    description = extract_action_param(siemplify, param_name='Description', print_value=True)

    tactics = string_to_multi_value(extract_action_param(siemplify, param_name='Tactics', print_value=True))

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = 'Failed to create hunting rule'

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

        custom_hunting_rule = manager.create_custom_hunting_rule(
            query=query,
            display_name=display_name,
            description=description,
            tactics=tactics
        )

        if custom_hunting_rule:
            output_message = f'Successfully created {PRODUCT_NAME} hunting rule'
            siemplify.result.add_result_json(custom_hunting_rule.to_json())

    except Exception as e:
        output_message = f"Error executing action '{CREATE_CUSTOM_HUNTING_RULES_SCRIPT_NAME}'. Reason: {e}"
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
