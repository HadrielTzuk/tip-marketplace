from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv, \
    convert_comma_separated_to_list
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, ENRICH_ASSETS_SCRIPT_NAME, ENRICHMENT_PREFIX, \
    GOOGLE_SERVICE_ACCOUNT_VALUE, GOOGLE_COMPUTE_ADDRESS_VALUE
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterInvalidJsonException, \
    GoogleSecurityCommandCenterInvalidProject
from UtilsManager import get_entity_original_identifier


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ASSETS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    organization_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, print_value=True,
                                                  param_name="Organization ID")
    service_account_string = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="User's Service Account", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # action parameters
    asset_resource_names_string = extract_action_param(siemplify, param_name="Asset Resource Names", is_mandatory=True,
                                                       print_value=True)
    asset_resource_names = convert_comma_separated_to_list(asset_resource_names_string)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_assets, not_found_assets, failed_assets, enriched_entities = [], [], [], []
    json_results = []

    try:
        manager = GoogleSecurityCommandCenterManager(api_root=api_root, organization_id=organization_id,
                                                     service_account_string=service_account_string,
                                                     verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        assets = manager.get_asset_details(resource_names=asset_resource_names)
        asset_resource_names_from_response = [asset.asset_name for asset in assets]
        # Assets that not the part of response, did not find information at all
        not_found_assets = [asset for asset in asset_resource_names if asset not in asset_resource_names_from_response]
        successful_assets = [asset for asset in asset_resource_names if asset in asset_resource_names_from_response]

        for entity in siemplify.target_entities:
            entity_identifier = get_entity_original_identifier(entity)
            siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")
            suitable_asset = None
            for asset in assets:
                if asset.resource_type == GOOGLE_SERVICE_ACCOUNT_VALUE:
                    if asset.resource_properties.get('email', '') == entity_identifier:
                        suitable_asset = asset
                elif asset.resource_type == GOOGLE_COMPUTE_ADDRESS_VALUE:
                    if asset.resource_properties.get('address', '') == entity_identifier:
                        suitable_asset = asset
                elif asset.resource_name == entity_identifier:
                    suitable_asset = asset
                else:
                    siemplify.LOGGER.info(f"Asset {asset.asset_name} doesn't have matching with {entity_identifier}")
                    failed_assets.append(asset.asset_name)

            if not suitable_asset:
                siemplify.LOGGER.info(f"Entity {entity_identifier} is not enriching. Skipping.")
                continue

            entity.additional_properties.update(suitable_asset.to_enrichment_data(prefix=ENRICHMENT_PREFIX))
            entity.is_enriched = True
            siemplify.result.add_entity_table(entity_identifier, flat_dict_to_csv(suitable_asset.to_table()))

            enriched_entities.append(entity)
            siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")

        for asset in assets:
            json_result = asset.to_json()
            json_result['siemplify_asset_display_name'] = asset.get_user_friendly_name() or asset
            json_results.append({
                'asset_name': asset.asset_name,
                'asset_result': json_result
            })

        if successful_assets:
            siemplify.result.add_result_json(json_results)
            siemplify.update_entities(enriched_entities)
            output_message += f"Successfully enriched the following assets using information from " \
                              f"{INTEGRATION_DISPLAY_NAME}: {', '.join(successful_assets)}\n"

            if not_found_assets:
                output_message += f"Action wasn't able to enrich the following assets using information from " \
                                  f"{INTEGRATION_DISPLAY_NAME}: {', '.join(not_found_assets)}"

            if failed_assets:
                siemplify.LOGGER.info(f"Action wasn't able to find the following assets using information from "
                                      f"{INTEGRATION_DISPLAY_NAME}: {', '.join(failed_assets)}")
        else:
            result_value = False
            output_message = "None of the provided assets were enriched."

    except GoogleSecurityCommandCenterInvalidProject:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Project_id was not found in JSON payload provided in the parameter " \
                         "\"User's Service Account\". Please check."
    except GoogleSecurityCommandCenterInvalidJsonException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Invalid JSON payload provided in the parameter \"User's Service Account\". Please " \
                         "check the structure."

    except Exception as e:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action {ENRICH_ASSETS_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.exception(e)
        siemplify.LOGGER.error(output_message)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()