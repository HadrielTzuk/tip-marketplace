from SiemplifyAction import SiemplifyAction
from VectraManager import VectraManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import (
    INTEGRATION_NAME,
    PING_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Token",
                                           input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    try:
        vectra_manager = VectraManager(api_root, api_token, verify_ssl=verify_ssl, siemplify=siemplify)
        vectra_manager.test_connectivity()
        output_message = u"Successfully connected to the Vectra server with the provided connection parameters!"
        connectivity_result = True
        siemplify.LOGGER.info(u"Connection to API established, performing action {}".format(PING_SCRIPT_NAME))

    except Exception as e:
        output_message = u"Failed to connect to the Vectra server! Error is {}".format(e)
        connectivity_result = False
        siemplify.LOGGER.error(u"Connection to API failed, performing action {}".format(PING_SCRIPT_NAME))

        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, connectivity_result, output_message))
    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
