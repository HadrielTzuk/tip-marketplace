from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NGFWManager import NGFWManager
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"PaloAltoNGFW"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"PaloAltoNGFW - CommitChanges"
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)
    only_my_changes = extract_action_param(siemplify, param_name=u"Only My Changes", input_type=bool,
                                           print_value=True, is_mandatory=True)

    api = NGFWManager(api_root, username, password, siemplify.run_folder, verify_ssl=verify_ssl)
    api.CommitChanges(only_my_changes=only_my_changes)

    siemplify.end(u"Successfully committed changes.", u'true')


if __name__ == "__main__":
    main()
