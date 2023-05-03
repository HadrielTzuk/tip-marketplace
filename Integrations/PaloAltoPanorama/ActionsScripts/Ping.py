from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from PanoramaManager import PanoramaManager
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = u"Panorama - Ping"
PROVIDER_NAME = u"Panorama"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # Configuration.
    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Api Root")
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username")
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    api = PanoramaManager(server_address, username, password, verify_ssl, siemplify.run_folder)

    output_message = "Successfully connected to {}".format(server_address)
    result_value = 'true'

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()

