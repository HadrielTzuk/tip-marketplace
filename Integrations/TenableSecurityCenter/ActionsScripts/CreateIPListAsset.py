from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param
from constants import PROVIDER_NAME, CREATE_IP_LIST_ASSET_SCRIPT_NAME
from TenableManager import TenableSecurityCenterManager, TenableSecurityCenterException
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_IP_LIST_ASSET_SCRIPT_NAME
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

        server_address = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME,
                                                     param_name=u"Server Address", is_mandatory=True, print_value=True)
        username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username",
                                               is_mandatory=True, print_value=True)
        password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password",
                                               is_mandatory=True)
        use_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Use SSL",
                                              is_mandatory=True, input_type=bool, print_value=True)

        name = extract_action_param(siemplify, param_name=u"Name", is_mandatory=True, print_value=True)
        description = extract_action_param(siemplify, param_name=u"Description", is_mandatory=False, print_value=True)
        tag = extract_action_param(siemplify, param_name=u"Tag", is_mandatory=False, print_value=True)

        siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

        if scope_entities:
            # Create manager instance
            manager = TenableSecurityCenterManager(server_address, username, password, use_ssl)
            ips_csv = u",".join([entity.identifier for entity in scope_entities])
            asset = manager.create_ip_list_asset(
                name=name,
                description=description,
                tags=tag,
                ips=ips_csv
            )
            siemplify.result.add_result_json(asset.to_json())
            output_message = u"Successfully created new IP List Asset {} with the following IPs in Tenable.sc:\n " \
                             u"{}".format(name, u"\n".join([entity.identifier for entity in scope_entities]))
            result_value = True
        else:
            output_message = u"At least 1 IP entity should be available in order to create an IP List Asset."

    except Exception as e:
        output_message = u"Error executing action \"Create IP List Asset\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
