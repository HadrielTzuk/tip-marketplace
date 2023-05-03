from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from AnyRunManager import AnyRunManager
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    GET_REPORT_ACTION,
    DEFAULT_THRESHOLD,
    DEFAULT_SEARCH_LIMIT,
    SHA256_LENGTH,
    MD5_LENGTH,
    SHA1_LENGTH
)

INSIGHT_TITLE = 'Any.Run Report'
INSIGHT_DESCRIPTION = "Entity: {}\n Verdict: {}\n Threat Level: {} \n Score: {}"
ENTITY_TABLE_HEADER = '{} Any.Run Reports'

SUPPORTED_ENTITY_TYPES = [EntityTypes.URL, EntityTypes.FILEHASH, EntityTypes.FILENAME]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_REPORT_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration.
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")

    # Parameters
    threshold = extract_action_param(siemplify, param_name='Threshold', is_mandatory=True, input_type=int,
                                     default_value=DEFAULT_THRESHOLD, print_value=True)
    search_limit = extract_action_param(siemplify, param_name='Search in last x scans', is_mandatory=True,
                                        input_type=int, default_value=DEFAULT_SEARCH_LIMIT, print_value=True)
    create_insight = extract_action_param(siemplify, param_name='Create Insight?', is_mandatory=False, input_type=bool,
                                          print_value=True)
    fetch_latest_report = extract_action_param(siemplify, param_name='Fetch latest report?', is_mandatory=False,
                                               input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_messages = []
    json_results = {}
    successful_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = AnyRunManager(
            api_key=api_key,
            siemplify_logger=siemplify.LOGGER
        )
        all_history_items = manager.get_analysis_history(limit=search_limit)
        if all_history_items:
            for entity in suitable_entities:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                if entity.entity_type == EntityTypes.FILEHASH and len(entity.identifier) not in [SHA256_LENGTH, MD5_LENGTH,
                                                                                                 SHA1_LENGTH]:
                    siemplify.LOGGER.error("Not supported hash type. Provide either MD5, SHA-256 or SHA-1.")
                    failed_entities.append(entity)
                    siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))
                    continue

                if entity.entity_type in [EntityTypes.URL, EntityTypes.FILENAME]:
                    report_uuids = [item.related.rsplit('/', 1)[-1] for item in all_history_items if item.name ==
                                    entity.identifier]
                else:
                    report_uuids = [item.related.rsplit('/', 1)[-1] for item in all_history_items if entity.identifier in
                                    item.hashes]

                if report_uuids:
                    reports = []
                    if fetch_latest_report:
                        reports.append(manager.get_report(uuid=report_uuids[0]))
                    else:
                        for uuid in report_uuids:
                            reports.append(manager.get_report(uuid=uuid))
                    if reports:
                        siemplify.LOGGER.info(
                            'Found Any.Run reports for the following entity: {}'.format(entity.identifier))
                        successful_entities.append(entity)
                        entity.is_suspicious = any(r.score > threshold for r in reports)
                        json_results[entity.identifier] = [rep.to_json() for rep in reports]
                        siemplify.result.add_entity_table(ENTITY_TABLE_HEADER.format(entity.identifier),
                                                          construct_csv([report.to_csv() for report in reports]))
                        if create_insight:
                            for rep in reports:
                                siemplify.create_case_insight(INTEGRATION_NAME, INSIGHT_TITLE,
                                                              INSIGHT_DESCRIPTION.format(entity.identifier,
                                                                                         rep.threat_text,
                                                                                         rep.threat_level,
                                                                                         rep.score),
                                                              entity.identifier, 0, 0)
                    else:
                        failed_entities.append(entity)
                else:
                    failed_entities.append(entity)

                siemplify.LOGGER.info("Finished processing entity {}".format(entity.identifier))

        if successful_entities:
            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_messages.append('Found Any.Run reports for the following entities:\n {}'.format(
                "\n".join([entity.identifier for entity in successful_entities])))

        if failed_entities:
            output_messages.append("Failed to find Any.Run reports for the following entities:\n {}"
                                   .format("\n".join([entity.identifier for entity in failed_entities])))

        output_message = '\n'.join(output_messages)

        if not successful_entities:
            output_message = "No Any.Run reports were found."
            result_value = False

    except Exception as e:
        output_message = "Error executing action \"Get Report\". Reason: {}".format(e)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()