import json
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from constants import PROVIDER_NAME, RUN_ASSET_SCAN_SCRIPT_NAME
from TenableManager import TenableSecurityCenterManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TenableExceptions import AssetNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_ASSET_SCAN_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Server Address",
                                                 is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password",
                                           is_mandatory=True)
    use_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Use SSL",
                                          is_mandatory=True, input_type=bool, print_value=True)

    scan_name = extract_action_param(siemplify, param_name=u"Scan Name", is_mandatory=True, print_value=True)
    asset_name = extract_action_param(siemplify, param_name=u"Asset Name", is_mandatory=True, print_value=True)
    policy_id = extract_action_param(siemplify, param_name=u"Policy ID", is_mandatory=True, input_type=int,
                                     print_value=True)
    repository_id = extract_action_param(siemplify, param_name=u"Repository ID", is_mandatory=True, input_type=int,
                                         print_value=True)
    description = extract_action_param(siemplify, param_name=u"Description", print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = u""

    try:
        # Create manager instance
        manager = TenableSecurityCenterManager(server_address, username, password, use_ssl)
        result = manager.get_scan_results(scan_name, asset_name, policy_id, repository_id, description)

        if result:
            siemplify.result.add_result_json(result.to_json())
            output_messages = u"Successfully started asset scan {} in Tenable.sc.".format(asset_name)

    except AssetNotFoundException:
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_messages = u"Error executing action \"Run Asset Scan\". Reason: Asset {} was not found in Tenable.sc."\
            .format(asset_name)
    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}. Error: {}".format(RUN_ASSET_SCAN_SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_messages = u"Error executing action \"Run Asset Scan\". Reason: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Messages: {}".format(output_messages))

    siemplify.end(output_messages, result_value, status)


if __name__ == "__main__":
    main()
