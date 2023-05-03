from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from McAfeeATDManager import McAfeeATDManager
from TIPCommon import extract_configuration_param, construct_csv
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, GET_ANALYZER_PROFILES_SCRIPT_NAME
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = GET_ANALYZER_PROFILES_SCRIPT_NAME
    siemplify.script_name = GET_ANALYZER_PROFILES_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        atd_manager = McAfeeATDManager(api_root=api_root,
                                       username=username,
                                       password=password,
                                       verify_ssl=verify_ssl)

        profiles = atd_manager.get_analyzer_profiles()
        for profile in profiles:
            profile['Profile ID'] = profile['vmProfileid']

        siemplify.result.add_result_json(json.dumps(profiles))
        siemplify.result.add_data_table("Analyzer Profiles", construct_csv(profiles))
        output_message = 'Profiles data attached'
        atd_manager.logout()

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {GET_ANALYZER_PROFILES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{GET_ANALYZER_PROFILES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
