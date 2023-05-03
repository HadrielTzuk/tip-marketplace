from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv
from utils import string_to_multi_value
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    MARK_AS_THREAT_SCRIPT_NAME,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = MARK_AS_THREAT_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    threat_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Threat IDs', is_mandatory=True,
                                                            print_value=True))

    status = EXECUTION_STATE_COMPLETED
    success_threats, failed_threats, json_results = [], [], []
    result_value = True

    try:
        manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                            verify_ssl=verify_ssl,
                                                            force_check_connectivity=True)
        for threat_id in threat_ids:
            try:
                manager.mark_as_threat([threat_id])
                threat = manager.get_threat_or_raise(threat_id)
                json_results.append(
                    threat.to_threat_json(marked=bool(manager.get_blacklist_with_hash(threat.hash_value)))
                )
                (success_threats if threat.is_true_positive else failed_threats).append(threat_id)
            except Exception as e:
                siemplify.LOGGER.error('Failed to mark as threat with ID {}'.format(threat_id))
                siemplify.LOGGER.exception(e)
                failed_threats.append(threat_id)

        if success_threats:
            output_message = 'Successfully marked the following threats in {}:\n{}\n'\
                .format(PRODUCT_NAME, ', '.join(success_threats))
            if failed_threats:
                output_message += "Action wasn't able to mark the following threats in {}:\n{}\n"\
                    .format(PRODUCT_NAME, ', '.join(failed_threats))
        else:
            result_value = False
            output_message = 'No threats were marked.'

        if json_results:
            siemplify.result.add_result_json(json_results)

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(MARK_AS_THREAT_SCRIPT_NAME, e)
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
