from MicrosoftAzureSentinelManager import MicrosoftAzureSentinelManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import UPDATE_ALERT_RULE_SCRIPT_NAME, INTEGRATION_NAME, PRODUCT_NAME
from utils import string_to_multi_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_ALERT_RULE_SCRIPT_NAME
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

    alert_rule_id = extract_action_param(siemplify, param_name='Alert Rule ID', is_mandatory=True, print_value=True)
    enable_alert_rule = extract_action_param(siemplify, param_name='Enable Alert Rule', print_value=True,
                                             input_type=bool)
    name = extract_action_param(siemplify, param_name='Name', print_value=True)
    severity = extract_action_param(siemplify, param_name='Severity', print_value=True)
    query = extract_action_param(siemplify, param_name='Query', print_value=True)
    frequency = extract_action_param(siemplify, param_name='Frequency', print_value=True)
    lookup_period = extract_action_param(siemplify, param_name='Period of Lookup Data', print_value=True)
    trigger_operator = extract_action_param(siemplify, param_name='Trigger Operator', print_value=True)
    trigger_threshold = extract_action_param(siemplify, param_name='Trigger Threshold', print_value=True,
                                             input_type=int)
    enable_suppression = extract_action_param(siemplify, param_name='Enable Suppression', print_value=True,
                                              input_type=bool)
    suppression_duration = extract_action_param(siemplify, param_name='Suppression Duration', print_value=True)
    description = extract_action_param(siemplify, param_name='Description', print_value=True)
    tactics = string_to_multi_value(extract_action_param(siemplify, param_name='Tactics', print_value=True))

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = f'Successfully updated {PRODUCT_NAME} alert rule with ID {alert_rule_id}'
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        MicrosoftAzureSentinelManager.validate_tactics(tactics=tactics)
        MicrosoftAzureSentinelManager.validate_alert_rule_severities(severities=[severity] if severity else None)
        MicrosoftAzureSentinelManager.validate_trigger_operators(
            trigger_operators=[trigger_operator] if trigger_operator else None)
        MicrosoftAzureSentinelManager.validate_duration(frequency)
        MicrosoftAzureSentinelManager.validate_duration(lookup_period)
        MicrosoftAzureSentinelManager.validate_duration(suppression_duration)

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

        alert_rule = manager.update_alert_rule(
            alert_rule_id=alert_rule_id,
            enable_alert_rule=enable_alert_rule,
            name=name,
            severity=severity,
            query=query,
            frequency=frequency,
            lookup_period=lookup_period,
            trigger_operator=trigger_operator,
            trigger_threshold=trigger_threshold,
            enable_suppression=enable_suppression,
            suppression_duration=suppression_duration,
            description=description,
            tactics=tactics
        )

        siemplify.result.add_result_json(alert_rule.to_json())

        siemplify.LOGGER.info(output_message)
    except Exception as e:
        output_message = f"Error executing action '{UPDATE_ALERT_RULE_SCRIPT_NAME}'. Reason: {e}"
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
