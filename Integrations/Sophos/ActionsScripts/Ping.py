from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SophosManager import SophosManager
from TIPCommon import extract_configuration_param
from constants import PING_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                           is_mandatory=True, input_type=unicode)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                           is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    siem_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"SIEM API Root",
                                                input_type=unicode)

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Key",
                                          input_type=unicode)

    base64_payload = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name=u"Base 64 Auth Payload", input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl,
                      siem_api_root=siem_api_root, api_key=api_key, api_token=base64_payload,
                      test_connectivity=True)

        status = EXECUTION_STATE_COMPLETED
        output_message = u"Successfully connected to the {} server with the provided connection parameters!.".format(INTEGRATION_NAME)
        result_value = True

    except Exception as e:
        output_message = u"Failed to connect to the Sophos server! Error is {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
