from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from APIVoidManager import APIVoidManager
from TIPCommon import extract_configuration_param

SCRIPT_NAME = u"APIVoid"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=SCRIPT_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=SCRIPT_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=SCRIPT_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    apivoid_manager = APIVoidManager(api_root, api_key, verify_ssl=verify_ssl)

    # Test connectivity
    apivoid_manager.test_connectivity()
    siemplify.end(u"Connected successfully.", 'true')


if __name__ == '__main__':
    main()