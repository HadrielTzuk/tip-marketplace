from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, ENRICH_ENTITIES_ACTION, ENRICH_PREFIX
from TIPCommon import extract_configuration_param, construct_csv
from SCCMManager import SCCMManager
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# Constants
SUPPORTED_ENTITY_TYPES = [EntityTypes.USER, EntityTypes.HOSTNAME, EntityTypes.ADDRESS]
TABLE_HEADER = "MS SCCM enrichment results for {}"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENTITIES_ACTION
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    json_results = {}
    successful_entities = []
    failed_entities = []

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Init Integration Configurations
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    domain = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                         is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        manager = SCCMManager(server_address, domain, username, password)
        target_entities = [
            entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES
        ]

        if target_entities:
            for entity in target_entities:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                if entity.entity_type == EntityTypes.USER:
                    entity_report = manager.enrich_user(entity.identifier)
                elif entity.entity_type == EntityTypes.HOSTNAME:
                    entity_report = manager.enrich_host(entity.identifier)
                else:
                    entity_report = manager.enrich_address(entity.identifier)

                if entity_report:
                    enrichment_data = entity_report.to_enrichment_data(prefix=ENRICH_PREFIX)
                    entity.additional_properties.update(enrichment_data)
                    entity.is_enriched = True
                    successful_entities.append(entity)

                    # JSON result
                    json_results[entity.identifier] = entity_report.to_json()
                    siemplify.result.add_entity_table(
                        TABLE_HEADER.format(entity.identifier),
                        construct_csv(entity_report.to_table())
                    )
                else:
                    failed_entities.append(entity)

                siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message = "Following entities were enriched with SCCM data: \n {} ".format(
                "\n ".join([entity.identifier for entity in successful_entities])
            )

        if failed_entities:
            output_message += "\nSCCM data for the following entities were not found: \n {}  ".format(
                "\n ".join([entity.identifier for entity in failed_entities])
            )

        if not successful_entities:
            output_message = "No entities were enriched"
            result_value = False

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}. Error: {}".format(ENRICH_ENTITIES_ACTION, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to connect to the Microsoft SCCM instance! The reason is {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "Status: {}, Result Value: {}, Output Message: {}"
        .format(status, result_value, output_message)
    )

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
