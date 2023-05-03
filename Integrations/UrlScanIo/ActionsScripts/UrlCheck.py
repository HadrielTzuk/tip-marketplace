import json
import sys
import time
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from UrlScanManager import UrlScanManager
from UrlScanParser import UrlScanParser
from UtilsManager import get_entity_original_identifier, get_screenshot_content_base64
from constants import INTEGRATION_NAME, URL_CHECK_ACTION_NAME, VISIBILITY_MAPPER, REPORT_LINK_TITLE, SCREENSHOT_TITLE, \
    DEFAULT_THRESHOLD, ATTACHMENT_FILE_NAME
from exceptions import UrlDnsScanError
from Siemplify import InsightSeverity, InsightType


def start_operation(siemplify, manager, suitable_entities):
    visibility = extract_action_param(siemplify, param_name="Visibility", print_value=True,
                                      default_value=VISIBILITY_MAPPER['public'])

    failed_entities, successful_entities, dns_failed_entities, result_value = [], [], [], {}
    output_message = ''
    status = EXECUTION_STATE_INPROGRESS
    result_value = {
        'in_progress': {},
        'completed': {},
        'failed': [],
        'dns_failed': []
    }

    for entity in suitable_entities:
        try:
            siemplify.LOGGER.info("Started submitting entity: {}".format(get_entity_original_identifier(entity)))

            submit_scan_id = manager.submit_url_for_scan(url=get_entity_original_identifier(entity),
                                                         visibility=VISIBILITY_MAPPER[visibility])

            result_value['in_progress'][get_entity_original_identifier(entity)] = submit_scan_id
            successful_entities.append(get_entity_original_identifier(entity))
            # Stop action not to reach limit of requests
            pause_action_execution()

            siemplify.LOGGER.info("Finish submitting entity: {}".format(get_entity_original_identifier(entity)))

        except UrlDnsScanError as err:
            dns_failed_entities.append(get_entity_original_identifier(entity))
            result_value['dns_failed'].append(get_entity_original_identifier(entity))
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(err)
        except Exception as err:
            failed_entities.append(get_entity_original_identifier(entity))
            result_value['failed'].append(get_entity_original_identifier(entity))
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(err)

    if successful_entities:
        output_message += "Successfully submitted the following URLs for scan: \n {} \n" \
            .format(', '.join(successful_entities))
        result_value = json.dumps(result_value)

    if failed_entities:
        output_message += "Action wasn’t able to submitted the following URLs for scan: \n {} \n" \
            .format(', '.join(failed_entities))

    if not successful_entities:
        if failed_entities:
            output_message = "Action wasn’t able to scan the following URLs using {}: \n {} \n" \
                .format(INTEGRATION_NAME, ', '.join(failed_entities))

        if dns_failed_entities:
            output_message += "The following entities: {} cannot be scanned using {}."\
                .format(', '.join(dns_failed_entities), INTEGRATION_NAME)

        if not failed_entities and not dns_failed_entities:
            output_message = "No entities were scanned."

        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, scan_report, suitable_entities):
    completed_entities = {}

    for entity, scan_id in scan_report['in_progress'].items():
        try:
            url_report = manager.get_url_scan_report(scan_id=scan_id)
            if url_report:
                completed_entities[entity] = url_report.to_json()
            # Stop action not to reach limit of requests
            pause_action_execution()
        except Exception as err:
            scan_report['failed'].append(entity)
            siemplify.LOGGER.error("An error occurred when checking status for url {}".format(entity))
            siemplify.LOGGER.exception(err)

    for key in completed_entities.keys():
        scan_report['in_progress'].pop(key)
    # Update completed entities with completed_entities dict including json_result
    scan_report['completed'].update(completed_entities)

    if scan_report['in_progress']:
        status = EXECUTION_STATE_INPROGRESS
        result_value = json.dumps(scan_report)
        output_message = "Waiting for results for the following entities: \n {} \n"\
            .format(", ".join(scan_report['in_progress'].keys()))
    else:
        output_message, result_value, status = finish_operation(siemplify=siemplify, manager=manager,
                                                                suitable_entities=suitable_entities,
                                                                completed_entities=scan_report['completed'],
                                                                failed_entities=scan_report['failed'],
                                                                dns_failed_entities=scan_report['dns_failed'])

    return output_message, result_value, status


def finish_operation(siemplify, manager, suitable_entities, completed_entities, failed_entities, dns_failed_entities):
    threshold = extract_action_param(siemplify, param_name="Threshold", print_value=True, input_type=int, default_value=DEFAULT_THRESHOLD)
    create_insight = extract_action_param(siemplify, param_name="Create Insight", print_value=True, input_type=bool, default_value=True)
    only_suspicious_insight = extract_action_param(siemplify, param_name="Only Suspicious Insight", print_value=True, input_type=bool, default_value=False)
    add_screenshot_to_insight = extract_action_param(siemplify, param_name="Add Screenshot To Insight", print_value=True, input_type=bool, default_value=False)
     
    parser = UrlScanParser()

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    failed_entities = failed_entities
    dns_failed_entities = dns_failed_entities
    successful_entities = []
    suspicious_entities = []
    json_results = {}

    for entity in suitable_entities:
        if get_entity_original_identifier(entity) in completed_entities.keys():
            entity_result = parser.build_url_object(completed_entities[get_entity_original_identifier(entity)])
            json_results[get_entity_original_identifier(entity)] = entity_result.to_shorten_json()

            if int(entity_result.score) >= threshold:
                entity.is_suspicious = True
                suspicious_entities.append(get_entity_original_identifier(entity))

            entity.additional_properties.update(entity_result.to_enrichment())

            entity.is_enriched = True
            successful_entities.append(entity)
            if entity_result.result_link:
                siemplify.result.add_link(REPORT_LINK_TITLE.format(get_entity_original_identifier(entity)),
                                          entity_result.result_link)

            try:
                if entity_result.screenshot_url:
                    screenshot_content = manager.get_screenshot_content(url=entity_result.screenshot_url)
                    base64_screenshot = get_screenshot_content_base64(screenshot_content)
                    siemplify.result.add_attachment(title=SCREENSHOT_TITLE.format(get_entity_original_identifier(entity)),
                                                    filename=ATTACHMENT_FILE_NAME.format(entity_result.uuid),
                                                    file_contents=base64_screenshot.decode())
                    
            except Exception as e:
                siemplify.LOGGER.info(f"Screenshot for entity {get_entity_original_identifier(entity)} is not available. Reason: {e}.")
                add_screenshot_to_insight = False
                
            screenshot = None
            if add_screenshot_to_insight:
                screenshot = base64_screenshot

            if create_insight:
                if only_suspicious_insight:
                    if int(entity_result.score) >= threshold:
                        siemplify.create_case_insight(
                        triggered_by=INTEGRATION_NAME,
                        title="URL Details",
                        content=entity_result.as_url_insight(screenshot_to_add=screenshot),
                        entity_identifier=get_entity_original_identifier(entity),
                        severity=InsightSeverity.INFO,
                        insight_type=InsightType.Entity,
                    )     
                else:    
                    siemplify.create_case_insight(
                        triggered_by=INTEGRATION_NAME,
                        title="URL Details",
                        content=entity_result.as_url_insight(screenshot_to_add=screenshot),
                        entity_identifier=get_entity_original_identifier(entity),
                        severity=InsightSeverity.INFO,
                        insight_type=InsightType.Entity,
                    )

    if successful_entities:
        output_message += "Following entities were scanned by {}: \n {} \n".format(INTEGRATION_NAME, ", ".join(
            [get_entity_original_identifier(entity) for entity in successful_entities]))
        siemplify.update_entities(successful_entities)

    if suspicious_entities:
        output_message += "Following entities were found suspicious by {}: \n {} \n"\
            .format(INTEGRATION_NAME, ", ".join(suspicious_entities))

    if failed_entities:
        output_message += "Action wasn’t able to scan the following URLs using {}: \n {} \n"\
            .format(INTEGRATION_NAME, ", ".join(failed_entities))

    if dns_failed_entities:
        output_message += "The following entities: {} cannot be scanned using {}."\
                .format(', '.join(dns_failed_entities), INTEGRATION_NAME)

    if not successful_entities:
        output_message = "No entities were scanned."
        result_value = False

    if json_results:
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = URL_CHECK_ACTION_NAME
    mode = "Main" if is_first_run else "Get Report"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    status = EXECUTION_STATE_INPROGRESS
    result_value = False
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]

    try:
        manager = UrlScanManager(api_key=api_key, verify_ssl=verify_ssl, force_check_connectivity=True)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, manager=manager,
                                                                   suitable_entities=suitable_entities)
        if status == EXECUTION_STATE_INPROGRESS:
            scan_report = result_value if result_value else extract_action_param(siemplify,
                                                                                 param_name="additional_data",
                                                                                 default_value='{}')
            output_message, result_value, status = query_operation_status(siemplify=siemplify, manager=manager,
                                                                          scan_report=json.loads(scan_report),
                                                                          suitable_entities=suitable_entities)

    except Exception as err:
        output_message = "General error performing action {} Reason: {}".format(URL_CHECK_ACTION_NAME, err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))

    siemplify.end(output_message, result_value, status)


def pause_action_execution():
    """
    The most efficient approach would be to wait at least 10 seconds before starting to poll, and then only polling
    2-second intervals with an eventual upper timeout in case the scan does not return.
    https://urlscan.io/about-api/#submission
    """
    time.sleep(2)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)

