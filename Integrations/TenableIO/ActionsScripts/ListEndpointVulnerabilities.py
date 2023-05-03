from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from TenableIOManager import TenableIOManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME, \
    DEFAULT_VULNERABILITIES_LIMIT, MAX_VULNERABILITIES_LIMIT, SEVERITIES
from SiemplifyDataModel import EntityTypes
from TenableIOExceptions import TenableIOException


SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key",
                                             is_mandatory=True)
    access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Key",
                                             is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    lowest_severity = extract_action_param(siemplify, param_name="Lowest Severity To Fetch", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Vulnerabilities To Return", input_type=int,
                                 default_value=DEFAULT_VULNERABILITIES_LIMIT, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_entities = []
    failed_entities = []
    json_results = {}
    assets = {}
    existing_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if limit < 1:
            raise Exception("\"Max Vulnerabilities To Return\" must be greater than 0.")
        elif limit > MAX_VULNERABILITIES_LIMIT:
            siemplify.LOGGER.info(f"\"Max Vulnerabilities To Return\" exceeded the maximum limit of "
                                  f"{MAX_VULNERABILITIES_LIMIT}. The default value {DEFAULT_VULNERABILITIES_LIMIT} "
                                  f"will be used")
            limit = DEFAULT_VULNERABILITIES_LIMIT

        manager = TenableIOManager(api_root=api_root, secret_key=secret_key, access_key=access_key,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        for entity in suitable_entities:
            for asset in manager.list_assets():
                if entity.identifier in asset.ipv4 or entity.identifier in asset.ipv6 or entity.identifier in asset.netbios_name:
                    existing_entities.append(entity)
                    assets[entity.identifier] = asset.id
                    break

        not_found_entities = list(set(suitable_entities) - set(existing_entities))

        for entity in existing_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            try:
                vulnerabilities = manager.get_endpoint_vulnerabilities(
                    asset_id=assets.get(entity.identifier),
                    severities=SEVERITIES[SEVERITIES.index(lowest_severity.lower()):] if lowest_severity else [],
                    limit=limit
                )

                if vulnerabilities:
                    successful_entities.append(entity)
                    json_results[entity.identifier] = [vuln.to_json() for vuln in vulnerabilities]

                    siemplify.result.add_entity_table(
                        entity.identifier,
                        construct_csv([vuln.to_table() for vuln in vulnerabilities])
                    )
                else:
                    failed_entities.append(entity)
            except TenableIOException as e:
                siemplify.LOGGER.error(f"Failed processing entity: {entity.identifier}: Error is: {e}")
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += "Successfully listed vulnerabilities related to the following endpoints in {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in successful_entities]))

        if not_found_entities:
            output_message += "\nAction wasn't able to find the following endpoints in {}: \n{}" \
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in not_found_entities]))

        if failed_entities:
            output_message += "\nNo vulnerabilities were found for the following endpoints: \n{}"\
                .format("\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            result = False
            output_message = "No vulnerabilities were found for the provided endpoints."

        if not existing_entities:
            result = False
            output_message = "Provided endpoints were not found in Tenable.io"

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
