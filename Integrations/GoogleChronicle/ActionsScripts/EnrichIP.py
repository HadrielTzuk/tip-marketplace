from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict
from GoogleChronicleManager import GoogleChronicleManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import consts
import json


SCRIPT_NAME = "Enrich IP"
ENRICHMENT_PREFIX = "G_Chronicle"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="User's Service Account",
                                        is_mandatory=True)
    api_root = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                           param_name="API Root", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(e)
        siemplify.end("Unable to parse credentials as JSON. Please validate creds.", "false", EXECUTION_STATE_FAILED)

    lowest_suspicious_severity = extract_action_param(siemplify, param_name="Lowest Suspicious Severity",
                                                      is_mandatory=True, print_value=True)
    mark_na_suspicious = extract_action_param(siemplify, param_name="Mark Suspicious N/A Severity", is_mandatory=False,
                                              print_value=True, default_value=False, input_type=bool)
    create_insight = extract_action_param(siemplify, param_name="Create Insight", is_mandatory=False,
                                          print_value=True, default_value=True, input_type=bool)
    only_suspicious_insight = extract_action_param(siemplify, param_name="Only Suspicious Insight", is_mandatory=False,
                                                   print_value=True, default_value=True, input_type=bool)

    lowest_suspicious_severity = consts.IOC_SEVERITIES.get(lowest_suspicious_severity.lower())

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    output_message = ""
    result_value = "false"

    try:
        manager = GoogleChronicleManager(api_root=api_root, verify_ssl=verify_ssl, **creds)

        for entity in siemplify.target_entities:
            is_suspicious = False
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                siemplify.LOGGER.info("Fetching information for address {}".format(entity.identifier))
                ioc_details = manager.get_ioc_details(ip=entity.identifier)
                
                siemplify.LOGGER.info("Found information about {}. Highest source severity: {}".format(
                    entity.identifier, ioc_details.highest_source_severity[0]))

                entity.additional_properties.update(ioc_details.as_enrichment(prefix=ENRICHMENT_PREFIX))
                entity.is_enriched = True

                json_results[entity.identifier] = ioc_details.raw_data

                if ioc_details.highest_source_severity[1] >= lowest_suspicious_severity or \
                        (ioc_details.highest_source_severity[1] == 0 and mark_na_suspicious):
                    # If at least one of the sources of the IOC have severity gte then lowest_suspicious_severity
                    # or if all have n/a severity and mark_na_suspicious - mark the entity as suspicious
                    siemplify.LOGGER.info("Marking entity as suspicious.")
                    entity.is_suspicious = True
                    is_suspicious = True

                if create_insight and not only_suspicious_insight:
                    siemplify.add_entity_insight(entity, ioc_details.to_insight())
                elif create_insight and only_suspicious_insight and is_suspicious:
                    siemplify.add_entity_insight(entity, ioc_details.to_insight())

                siemplify.result.add_entity_table(entity.identifier, construct_csv(ioc_details.to_table()))
                siemplify.result.add_entity_link(entity.identifier, ioc_details.uri[0] if ioc_details.uri else "")

                successful_entities.append(entity)
                siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully enriched the following IPs from Google Chronicle:\n   {}".format(
                "\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = "true"

        else:
            output_message += "No entities were enriched."

        if failed_entities:
            output_message += "\n\nAction was not able to enrich the following IPs from Google Chronicle:\n   {}".format(
                "\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}"

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
