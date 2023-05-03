from typing import List

from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from ArmisManager import ArmisManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes, InsightType, InsightSeverity
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict
from consts import (
    INTEGRATION_NAME,
    ENRICH_ENTITIES,
    ENDPOINT_INSIGHT_TITLE
)

# Fix misalignment of MAC entity type
EntityTypes.MACADDRESS = EntityTypes.MACADDRESS.upper()
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.MACADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, ENRICH_ENTITIES)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root', is_mandatory=True,
                                           print_value=True)
    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Secret', is_mandatory=True,
                                             print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL', input_type=bool,
                                             default_value=True, is_mandatory=False, print_value=True)

    # Action parameters
    create_endpoint_insight = extract_action_param(siemplify, param_name="Create Endpoint Insight", input_type=bool, is_mandatory=False,
                                                   print_value=True, default_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    successful_entities: List[str] = []
    failed_entities: List[str] = []

    already_processed_device_ids: List[str] = []
    endpoints_insights: List[str] = []
    json_results = {}

    try:
        manager = ArmisManager(api_root=api_root, api_secret=api_secret, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue
                entity.identifier = entity.identifier.strip()
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                if entity.entity_type == EntityTypes.ADDRESS:
                    siemplify.LOGGER.info("Fetching information for IP address {}".format(entity.identifier))
                    device_info = manager.get_device_by_ip(ip_address=entity.identifier)
                elif entity.entity_type == EntityTypes.MACADDRESS:
                    siemplify.LOGGER.info("Fetching information for MAC address {}".format(entity.identifier))
                    device_info = manager.get_device_by_mac(mac_address=entity.identifier)
                else:
                    continue
                if device_info:
                    siemplify.LOGGER.info("Found information about {}. Risk level: {}".format(entity.identifier,
                                                                                              device_info.verbal_risk_level))
                    entity.additional_properties.update(device_info.as_enrichment())
                    entity.is_enriched = True
                    json_results[entity.identifier] = device_info.as_json()
                    siemplify.result.add_entity_link(f'{entity.identifier}', device_info.case_wall_report_link)

                    if device_info.device_id not in already_processed_device_ids:
                        already_processed_device_ids.append(device_info.device_id)
                        siemplify.result.add_entity_table(f'{entity.identifier}',
                                                          construct_csv(device_info.as_enrichment_csv_table()))
                        if create_endpoint_insight:
                            endpoints_insights.append(device_info.as_insight(entity.identifier))

                    successful_entities.append(entity)
                    siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))
                else:
                    failed_entities.append(entity)
                    siemplify.LOGGER.error(f"Failed to find device details")

            except Exception as error:
                failed_entities.append(entity)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(error)

        if successful_entities:
            output_message += "Successfully enriched the following entities using {}:\n  {}\n\n".format(
                INTEGRATION_NAME,
                "\n  ".join(entity.identifier for entity in successful_entities)
            )
            result_value = True
            siemplify.update_entities(successful_entities)
            if json_results:
                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

            if create_endpoint_insight and endpoints_insights:
                endpoints_insight_title = "Enriched {}".format('Endpoints' if len(endpoints_insights) > 1 else 'Endpoint')
                siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                              title=endpoints_insight_title,
                                              content="".join(endpoints_insights),
                                              entity_identifier="",
                                              severity=InsightSeverity.INFO,
                                              insight_type=InsightType.General)
            if failed_entities:
                output_message += "Action wasn't able to enrich the following entities using {}:\n  {}\n\n".format(
                    INTEGRATION_NAME,
                    "\n  ".join([entity.identifier for entity in failed_entities])
                )
        else:
            output_message += f"No entities were enriched."

    except Exception as error:
        output_message = f'Error execution action \"{ENRICH_ENTITIES}\". Reason: {error}'
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
