import json
import sys

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import add_prefix_to_dict, convert_dict_to_json_result_dict, output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotal import VirusTotalManager, URL_TYPE, ScanStatus, ENTITY_TASK_ID_KEY, \
    ENTITY_REPORT_KEY, ENTITY_STATUS_KEY, VirusTotalInvalidAPIKeyManagerError, VirusTotalLimitManagerError

VT_PREFIX = u"VT"
SCRIPT_NAME = u"VirusTotal - ScanURL"
IDENTIFIER = u"VirusTotal"

NO_PERMALINK = u'No permalink found in results.'


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = u"Main" if is_first_run else u"QueryState"
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Api Key",
                                          input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    #  INIT ACTION PARAMETERS:
    rescan_after_days = extract_action_param(siemplify, param_name=u'Rescan after days', is_mandatory=False,
                                             input_type=int, default_value=None)

    threshold = extract_action_param(siemplify, param_name=u'Threshold', is_mandatory=False,
                                     input_type=int, print_value=True, default_value=3)

    output_message = u""
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info(u"----------------- {} - Started -----------------".format(mode))

    try:
        manager = VirusTotalManager(api_key, verify_ssl)

        if is_first_run:
            try:
                entities_handle = start_operation(siemplify, manager, rescan_after_days)

                if entities_handle:
                    status = EXECUTION_STATE_INPROGRESS
                    result_value = json.dumps(entities_handle)
                    output_message += u"The following entities were submitted for analysis in VirusTotal:\n{}".format(
                        u"\n".join(entities_handle.keys())
                    )
                else:
                    result_value = u"false"
                    output_message += u"No URL entities were found in current scope."

            except VirusTotalInvalidAPIKeyManagerError as e:
                # Invalid key was passed - terminate action
                siemplify.LOGGER.error(u"Invalid API key was provided. Access is forbidden.")
                status = EXECUTION_STATE_FAILED
                result_value = u"false"
                output_message = u"Invalid API key was provided. Access is forbidden."

        else:
            entities_handle = json.loads(siemplify.parameters[u"additional_data"])
            query_output_message, result_value, status = query_operation_status(siemplify, manager, threshold,
                                                                                entities_handle)
            output_message += query_output_message

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message += u"\nGeneral error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info(u"----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


def start_operation(siemplify, manager, rescan_after_days):
    """
    Main ScanURL action
    :param siemplify: SiemplifyAction object
    :param manager: VirusTotal object
    :param rescan_after_days: action init param
    :return: {entities}
    """
    url_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]
    entities_handle = {}

    for entity in url_entities:
        try:
            # Search a file url in virusTotal
            entities_handle.update(
                manager.define_resource_status(get_entity_original_identifier(entity), URL_TYPE, rescan_after_days))

        except VirusTotalInvalidAPIKeyManagerError:
            # Invalid API key provided - raise
            raise

        except VirusTotalLimitManagerError:
            siemplify.LOGGER.info(u"API limit reached for entity {}".format(entity.identifier))
            entity_handle = {
                entity.identifier: {
                    ENTITY_REPORT_KEY: {},
                    ENTITY_TASK_ID_KEY: None,
                    ENTITY_STATUS_KEY: ScanStatus.LIMIT_REACHED
                }
            }
            entities_handle.update(entity_handle)

        except Exception as e:
            siemplify.LOGGER.error(u"An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(e)
            entity_handle = {get_entity_original_identifier(entity): {
                ENTITY_REPORT_KEY: {},
                ENTITY_TASK_ID_KEY: None,
                ENTITY_STATUS_KEY: ScanStatus.FAILED}
            }
            entities_handle.update(entity_handle)
    if not url_entities:
        siemplify.LOGGER.info(u"No URL entities were found in current scope.\n")
    return entities_handle


def query_operation_status(siemplify, manager, threshold, entities_handle):
    """
    Main ScanHash action
    :param siemplify: SiemplifyAction object
    :param manager: VirusTotal object
    :param threshold: action init param
    :param entities_handle: entities which should be checked
    :return: {output message, result, execution state}
    """

    output_message = u""
    missing_urls = []
    report_urls = []
    rescan_urls = []
    forbidden_urls = []
    json_results = {}
    failed_urls = []
    limit_urls = []
    entities_to_enrich = []
    is_risky = False

    for entity_identifier, entity_handle in entities_handle.items():
        task_id = entity_handle.get(ENTITY_TASK_ID_KEY)
        try:
            if task_id and entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.QUEUED:
                siemplify.LOGGER.info(u"Checking if task of {} has completed.".format(entity_identifier))
                # check if analysis completed
                entity_report = manager.is_scan_report_ready(task_id, URL_TYPE)
                if entity_report:
                    siemplify.LOGGER.info(u"Task of {} has completed.".format(entity_identifier))
                    # is_ready = True, fetch the report
                    entity_handle[ENTITY_STATUS_KEY] = ScanStatus.DONE
                    entity_handle[ENTITY_REPORT_KEY] = entity_report.to_json()
                else:
                    siemplify.LOGGER.info(u"Task of {} has NOT completed yet.".format(entity_identifier))

        except VirusTotalLimitManagerError:
            siemplify.LOGGER.info(u"API limit reached while checking if task of {} has completed.".format(entity_identifier))
            entity_handle[ENTITY_STATUS_KEY] = ScanStatus.LIMIT_REACHED

        except Exception as err:
            error_message = u"Error Rescan {} with task ID {}, Error: {}".format(
                entity_identifier, task_id, err.message)
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            entity_handle[ENTITY_STATUS_KEY] = ScanStatus.FAILED

    # Flag to determine the async action status - continue, end
    queued_items = dict(filter(lambda entity: entity[1][ENTITY_STATUS_KEY] == ScanStatus.QUEUED,
                               entities_handle.items()))

    if queued_items:
        siemplify.LOGGER.info(u"Continuing...the requested items are still queued for analysis")
        output_message = u"Continuing...the requested items are still queued for analysis"
        siemplify.end(output_message, json.dumps(entities_handle), EXECUTION_STATE_INPROGRESS)

    # Action END
    else:
        siemplify.LOGGER.info(u"All tasks are done")
        for entity_identifier, entity_handle in entities_handle.items():
            if entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.DONE and entity_handle.get(ENTITY_REPORT_KEY):
                siemplify.LOGGER.info(u"Collecting results for {}.".format(entity_identifier))

                if entity_handle.get(ENTITY_TASK_ID_KEY):
                    # Entity's last scan exceed the rescan days threshold - was rescan it.
                    siemplify.LOGGER.info(u"Entity {} was rescanned".format(entity_identifier))
                    rescan_urls.append(entity_identifier)
                else:
                    report_urls.append(entity_identifier)

                # Report enrichment & data table
                json_results[entity_identifier] = entity_handle.get(ENTITY_REPORT_KEY)
                try:
                    entity = [e for e in siemplify.target_entities if
                              get_entity_original_identifier(e) == entity_identifier][0]

                    try:
                        comments = manager.get_comments(entity.identifier)
                    except Exception as e:
                        siemplify.LOGGER.info(u"Unable to fetch comments for {}".format(entity.identifier))
                        siemplify.LOGGER.exception(e)
                        comments = []

                    # Fetch report
                    is_risky_entity = add_siemplify_results(
                        siemplify,
                        entity,
                        manager.get_url_report(entity_handle.get(ENTITY_REPORT_KEY)),
                        threshold,
                        comments
                    )

                    if is_risky_entity:
                        is_risky = True

                    entities_to_enrich.append(entity)
                except Exception as err:
                    error_message = u"Error on url {}: {}.".format(
                        entity_identifier,
                        err.message
                    )
                    siemplify.LOGGER.error(error_message)
                    siemplify.LOGGER.exception(err)

            elif entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.FAILED:
                failed_urls.append(entity_identifier)

            elif entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.FORBIDDEN:
                forbidden_urls.append(entity_identifier)

            elif entity_handle.get(ENTITY_STATUS_KEY) == ScanStatus.LIMIT_REACHED:
                limit_urls.append(entity_identifier)

            else:
                missing_urls.append(entity_identifier)

        if report_urls or rescan_urls:
            # Fetch report handle
            report_urls.extend(rescan_urls)
            output_message += u"Reports were fetched for the following urls: \n{}\n".format(
                u"\n".join(report_urls))

        if missing_urls:
            # Missing url handle
            output_message += u"\nThe following urls does not exist on VirusTotal (url was never scanned " \
                              u"before): \n{}\n".format(u"\n".join(missing_urls))

        if failed_urls:
            output_message += u"\nThe following urls have failed: \n{}\n".format(u"\n".join(failed_urls))

        if forbidden_urls:
            output_message += u"\nFailed to rescan the following urls (provided API Key is for public API, " \
                              u"but private API access is required): \n{}\n".format(u"\n".join(forbidden_urls))

        if limit_urls:
            output_message += u"\nReports were not fetched for the following urls due to reaching API request limitation: \n{}\n".format(
                u"\n".join(limit_urls))

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

        if entities_to_enrich:
            siemplify.update_entities(entities_to_enrich)

        return output_message, is_risky, EXECUTION_STATE_COMPLETED


def add_siemplify_results(siemplify, entity, report, threshold, comments=[]):
    """
    helper function for query_operation_status
    add report to entity
    :param siemplify: SiemplifyAction object
    :param entity: entity which will be added to result
    :param report: URL object created from url call response
    :param threshold: threshold param from siemplify object
    :param comments: List of the hash's comments
    :return: {bool}
    """
    is_risky = False
    entity.additional_properties.update(add_prefix_to_dict(report.to_enrichment_data(),
                                                           VT_PREFIX))
    entity.is_enriched = True

    siemplify.result.add_entity_table(get_entity_original_identifier(entity), construct_csv(report.build_engine_csv()))

    if comments:
        comments_table = construct_csv([comment.to_csv() for comment in comments])
        siemplify.result.add_data_table(u"Comments to {}".format(entity.identifier), comments_table)

    web_link = report.permalink if report.permalink else NO_PERMALINK
    siemplify.result.add_entity_link(get_entity_original_identifier(entity), web_link)

    positives = report.positives if report.positives else 0
    if int(threshold) <= positives:
        is_risky = True
        entity.is_suspicious = True

        insight_msg = u'VirusTotal - URL was marked as malicious by {0} of {1} engines. Threshold set to - {2}'.format(
            report.positives, report.total, threshold)

        siemplify.add_entity_insight(entity, insight_msg, triggered_by=IDENTIFIER)

    return is_risky


def get_entity_original_identifier(entity):
    """
    helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
