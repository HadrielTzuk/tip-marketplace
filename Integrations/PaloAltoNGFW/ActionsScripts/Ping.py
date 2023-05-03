from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = u"PaloAltoNGFW"


@output_handler
def main():

    siemplify = SiemplifyAction()
    siemplify.script_name = u"NGFW - Ping"
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    api = NGFWManager(api_root, username, password, siemplify.run_folder, verify_ssl=verify_ssl)

    output_message = u"Successfully connected to {}".format(api_root)
    result_value = u'true'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
