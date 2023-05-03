from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param
from constants import PROVIDER_NAME, ADD_IP_TO_LIST_ASSET_SCRIPT_NAME
from TenableManager import TenableSecurityCenterManager, TenableSecurityCenterException
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_IP_TO_LIST_ASSET_SCRIPT_NAME
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

        asset_name = extract_action_param(siemplify, param_name=u"Asset Name", is_mandatory=True, print_value=True)

        siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

        if scope_entities:
            # Create manager instance
            manager = TenableSecurityCenterManager(server_address, username, password, use_ssl)
            asset_id = manager.get_asset_id_by_asset_name(asset_name=asset_name)
            if not asset_id:
                raise Exception(u"Asset {} was not found in Tenable.sc.".format(asset_name))

            existing_asset = manager.get_asset_details(asset_id=asset_id, only_type_fields=True)
            ips_csv = u",".join([existing_asset.defined_ips, u",".join([entity.identifier for entity in scope_entities])])
            manager.update_ip_list_asset(asset_id=asset_id, ips=ips_csv)
            modified_asset = manager.get_asset_details(asset_id=asset_id, only_type_fields=False)
            siemplify.result.add_result_json(modified_asset.to_json())
            output_message = u"Successfully added the following IPs to the IP List Asset {} in Tenable.sc:\n{}"\
                .format(asset_name, u"\n".join([entity.identifier for entity in scope_entities]))
            result_value = True
        else:
            output_message = u"No IP addresses were added to the IP List Asset {0}".format(asset_name)

    except Exception as e:
        output_message = u"Error executing action \"Add IP to IP List Asset\". Reason: {}".format(e)
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
