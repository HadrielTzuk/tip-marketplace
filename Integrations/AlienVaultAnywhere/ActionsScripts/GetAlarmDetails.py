from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from AlienVaultManagerLoader import AlienVaultManagerLoader, ManagerVersionsEnum
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


INTEGRATION_NAME = "AlienVaultAnywhere"
SCRIPT_NAME = "Get Alarm Details"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Product Version',
                                          is_mandatory=True, default_value="V1")
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                                 is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          is_mandatory=True, default_value=True, input_type=bool)

    alarm_id = extract_action_param(siemplify, param_name=u"Alarm ID", is_mandatory=True,
                                            input_type=str,
                                            print_value=True)

    if version == "V1":
        siemplify.end(
            "This action is not supported for AlienVault Anywhere V1 integration. Please use V2.", 'false',
            EXECUTION_STATE_FAILED)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    json_results = {}
    result_value = "true"
    status = EXECUTION_STATE_COMPLETED

    try:
        alienvault_manager = AlienVaultManagerLoader.load_manager(version, server_address, username, password, use_ssl)
        alarm = alienvault_manager.get_alarm_by_id(alarm_id)

        siemplify.result.add_data_table("Alarm {} Details".format(alarm_id), flat_dict_to_csv(alarm.to_csv()))
        json_results = alarm.raw_data
        output_message = 'Successfully returned Alien Vault Anywhere alarm {} details'.format(alarm_id)

    except Exception as e:
        siemplify.LOGGER.error("Failed to get details about Alien Vault Anywhere alarm! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "Failed to get details about Alien Vault Anywhere alarm! Error is {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
