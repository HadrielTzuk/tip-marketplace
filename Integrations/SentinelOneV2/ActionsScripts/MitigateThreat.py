from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from utils import string_to_multi_value
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    MITIGATE_THREAT_SCRIPT_NAME,
    MITIGATION_MAPPING,
    QUARANTINE,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = MITIGATE_THREAT_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    mitigation_action = extract_action_param(siemplify, param_name="Mitigation action", is_mandatory=True,
                                             default_value=MITIGATION_MAPPING[QUARANTINE], print_value=True).lower()
    threat_ids = string_to_multi_value(extract_action_param(siemplify, param_name="Threat IDs", is_mandatory=True,
                                                            print_value=True))

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ''
    success_threats, failed_threats, mitigated_threats, json_results = [], [], [], []

    try:
        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl,
                                                            force_check_connectivity=True)
        for threat_id in threat_ids:
            try:
                threat = manager.get_threat_or_raise(threat_id)
                for mitigation_status in threat.mitigation_statuses:
                    if mitigation_status.has_action(mitigation_action):
                        mitigated_threats.append(threat_id)
                        break
                else:
                    affected_count = manager.mitigate_threat(mitigation_action, [threat_id])
                    if not affected_count:
                        raise
                    success_threats.append(threat_id)
                json_results.append(threat.to_mitigate_json(mitigation_action))
            except Exception as e:
                siemplify.LOGGER.error('Failed to mitigate Threat ID {}'.format(threat_id))
                siemplify.LOGGER.exception(e)
                failed_threats.append(threat_id)

        if success_threats:
            output_message += 'Successfully mitigated the following threats in {}:\n{}\n'\
                .format(PRODUCT_NAME, ', '.join(success_threats))

        if failed_threats:
            output_message += 'Action wasn\'t able to mitigate the following threats in {}:\n{}\n'\
                .format(PRODUCT_NAME, ', '.join(failed_threats))

        if mitigated_threats:
            output_message += 'The {} action was already applied to the following threats in {}:\n{}. ' \
                              'Note: those action can still be pending.\n'\
                .format(mitigation_action, PRODUCT_NAME, ', '.join(mitigated_threats))

        elif not success_threats:
            result_value = False
            output_message = 'No threats were mitigated.'

        if json_results:
            siemplify.result.add_result_json(json_results)

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(MITIGATE_THREAT_SCRIPT_NAME, e)
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
