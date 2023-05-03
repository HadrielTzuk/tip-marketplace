from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from AutoFocusManager import AutoFocusManager, COMPLETED, COOKIE, NOT_COMPLETED
from TIPCommon import extract_configuration_param, dict_to_flat, add_prefix_to_dict_keys, \
    construct_csv
import base64
import sys
import json


INTEGRATION_NAME = u'AutoFocus'
SCRIPT_NAME = u'HuntUrl'
SUPPORTED_ENTITIES = [EntityTypes.URL, ]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                           is_mandatory=True, input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    successful_entities = []
    hunts = {}
    failed_entities = []
    status = EXECUTION_STATE_COMPLETED
    output_message = u""

    try:
        autofocus_manager = AutoFocusManager(api_key)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                af_cookie, af_status = autofocus_manager.hunt_url(entity.identifier)

                siemplify.LOGGER.info(
                    u"Successfully started hunt for {0}. AF Cookie: {1}.".format(entity.identifier, af_cookie)
                )

                hunts[entity.identifier] = {
                    COOKIE: af_cookie,
                    u"completed": False
                }

                successful_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully initiated hunt for the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )
            status = EXECUTION_STATE_INPROGRESS

        else:
            output_message = u"No entities were enriched."

        if failed_entities:
            output_message += u"\n\nError occurred while initiating hunt for the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in failed_entities])
            )

        if successful_entities:
            output_message += u"\n\nWaiting for hunts to complete."

        result_value = json.dumps({
            u"hunts": hunts,
            u"successful_entities": successful_entities,
            u"failed_entities": failed_entities
        })

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def async_action():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)

    siemplify.LOGGER.info(u"================= Async - Param Init =================")

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)

    results_limit = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Results Limit",
                                          is_mandatory=False, input_type=int, default_value=None)

    siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

    error_entities = []
    successful_entities = []
    no_results_entities = []
    json_results = {}
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    action_details = json.loads(siemplify.parameters[u"additional_data"])
    hunts = action_details[u"hunts"]
    init_failed_entities = action_details[u"failed_entities"]
    init_success_entities = action_details[u"successful_entities"]
    current_status_report = u""
    all_completed = True

    try:
        autofocus_manager = AutoFocusManager(api_key)

        # Check if tasks have all completed
        for entity_identifier, hunt in hunts.items():
            try:
                if hunt.get(u"completed"):
                    siemplify.LOGGER.info(u"Hunt for {} already completed.".format(entity_identifier))
                    current_status_report += u"   {entity_identifier}: {percentage}%\n".format(
                        entity_identifier=entity_identifier,
                        percentage=100
                    )

                else:
                    siemplify.LOGGER.info(u"Checking status of the hunt for {}".format(entity_identifier))

                    results, af_status = autofocus_manager.hunt_url(entity_identifier, hunt[COOKIE])

                    if af_status == NOT_COMPLETED:
                        siemplify.LOGGER.info(u"Hunt haven't completed yet. Completed percentage: {}".format(results))

                        current_status_report += u"   {entity_identifier}: {percentage}%\n".format(
                            entity_identifier=entity_identifier,
                            percentage=results
                        )
                        all_completed = False

                    else:
                        # Hunt for entity has completed - percentage is 100
                        siemplify.LOGGER.info(u"Hunt completed.")
                        hunt[u"results"] = results
                        hunt[u"completed"] = True
                        current_status_report += u"   {entity_identifier}: {percentage}%\n".format(
                            entity_identifier=entity_identifier,
                            percentage=100
                        )

            except Exception as e:
                siemplify.LOGGER.info(u"Failed to check status of hunt for {}".format(entity_identifier))
                siemplify.LOGGER.exception(e)
                output_message = u"An error occurred while running action. Failed to check status of hunt for {}".format(
                    entity_identifier)
                status = EXECUTION_STATE_FAILED
                siemplify.end(output_message, u'false', status)

        if not all_completed:
            siemplify.LOGGER.info(
                u"Hunts have not completed yet. Waiting. Current status:\n\n{}".format(current_status_report)
            )
            output_message = u"Hunts have not completed yet. Waiting. Current status:\n\n{}".format(current_status_report)
            result_value = json.dumps({
                u"hunts": hunts,
                u"successful_entities": init_success_entities,
                u"failed_entities": init_failed_entities
            })
            status = EXECUTION_STATE_INPROGRESS
            siemplify.end(output_message, result_value, status)

        siemplify.LOGGER.info(u"All hunts have completed.")

        for entity_identifier, hunt in hunts.items():
            try:
                hunt_result = hunt.get(u"results", [])
                json_results[entity_identifier] = hunt_result

                if hunt_result:
                    siemplify.LOGGER.info(u"Found {} hits for {}".format(len(hunt_result), entity_identifier))

                    entity = convert_identifier_to_entity(siemplify, entity_identifier)

                    # Get hits and enrich the entity
                    count = 1

                    # Flatten the first hits (up to limit) and append a count
                    # prefix to identify info with its hit number
                    trimmed_hunt_results = hunt_result[:results_limit] if results_limit else hunt_result

                    siemplify.LOGGER.info(u"Enriching entity {}".format(entity_identifier))

                    for hit in trimmed_hunt_results:
                        flat_result = dict_to_flat(hit)
                        flat_result = add_prefix_to_dict_keys(flat_result, unicode(count))
                        flat_result = add_prefix_to_dict_keys(flat_result, u"AutoFocus")
                        entity.additional_properties.update(flat_result)
                        count += 1

                    # Attach all hits as csv
                    siemplify.LOGGER.info(u"Attaching table to entity {}".format(entity_identifier))
                    csv_output = construct_csv(trimmed_hunt_results)
                    siemplify.result.add_entity_table(entity.identifier, csv_output)

                    # Attach report
                    siemplify.LOGGER.info(u"Attaching json report for {}".format(entity_identifier))
                    base64_report = base64.b64encode(json.dumps(hunt_result, indent=4, sort_keys=True))

                    siemplify.result.add_entity_attachment(entity.identifier, u"AutoFocus Report", base64_report)

                    entity.is_enriched = True

                    siemplify.LOGGER.info(u"Marking {} as suspicious.".format(entity_identifier))
                    entity.is_suspicious = True

                    siemplify.LOGGER.info(u"Adding insight for {}".format(entity_identifier))
                    insight_msg = u'{} hits were found in AutoFocus'.format(len(hunt_result))
                    siemplify.add_entity_insight(entity, insight_msg, triggered_by=u'AutoFocus')

                    successful_entities.append(entity)

                else:
                    siemplify.LOGGER.info(u"No hits were found for {}".format(entity_identifier))
                    no_results_entities.append(entity_identifier)

            except Exception as e:
                error_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = u"The following entities were enriched by AutoFocus:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)

        else:
            output_message = u"No entities were enriched."

        if no_results_entities:
            output_message += u"\n\nNo hits were found for the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in no_results_entities])
            )

        if init_failed_entities:
            output_message += u"\n\nError occurred while initiating hunt for the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in init_failed_entities])
            )

        if error_entities:
            output_message += u"\n\nError occurred while running hunt for the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in error_entities])
            )

        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Async - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def convert_identifier_to_entity(siemplify, entity_identifier):
    for entity in siemplify.target_entities:
        if entity_identifier == entity.identifier:
            return entity

    raise Exception(u"Entity {} was not found in current scope".format(entity_identifier))


if __name__ == u"__main__":
    if len(sys.argv) < 3 or sys.argv[2] == u'True':
        main()
    else:
        async_action()
