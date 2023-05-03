from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from TIPCommon import extract_configuration_param

from McAfeeMvisionEDRManager import McAfeeMvisionEDRManager
from constants import PROVIDER_NAME

SCRIPT_NAME = u"McAfeeMvisionEDR - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="API Root",
                                           input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Username",
                                           input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Password",
                                           input_type=unicode)
    client_id = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="Client ID", input_type=unicode
    )
    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
    )
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    try:
        mvision_edr_manager = McAfeeMvisionEDRManager(
            api_root, username, password, client_id, client_secret, verify_ssl=verify_ssl
        )
        mvision_edr_manager.test_connectivity()
        output_message = u"Successfully connected to the McAfee Mvision EDR server with the provided connection parameters!"
        connectivity_result = True
        siemplify.LOGGER.info(u"Connection to API established, performing action {}".format(SCRIPT_NAME))

    except Exception as e:
        output_message = u"Failed to connect to the McAfee Mvision EDR server! Error is {}".format(e)
        connectivity_result = False
        siemplify.LOGGER.error(u"Connection to API failed, performing action {}".format(SCRIPT_NAME))

        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
