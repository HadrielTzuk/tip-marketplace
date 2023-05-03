import json
import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, unix_now
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, ENRICH_HASH_SCRIPT_NAME, DEFAULT_LIMIT, COMMENTS_TABLE_TITLE, \
    REPORT_LINK_TITLE, SIGMA_ANALYSIS_TITLE, MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH, DEFAULT_RESUBMIT_DAYS, COMPLETED, \
    DEFAULT_SANDBOX, WIDGET_THEME_MAPPING
from exceptions import ForceRaiseException, VirusTotalInvalidFormat
from UtilsManager import get_entity_original_identifier, convert_days_to_milliseconds
from VirusTotalParser import VirusTotalParser


def check_resubmission_day(siemplify, manager, suitable_entities, resubmit_days):
    """
    Check if entities should be resubmitted
    :param siemplify: {siemplify} Siemplify object
    :param manager: {VirusTotalManager} VirusTotalManager manager object
    :param suitable_entities: {list} list of siemplify entities
    :param resubmit_days: {int} amount of days to use for resubmission check
    :return: {tuple} entities_to_resubmit, entities_data, failed_entities_statuses
    """
    entities_to_resubmit = []
    entities_data = {}
    failed_entities_statuses = {}

    for entity in suitable_entities:
        entity_original_identifier = get_entity_original_identifier(entity)
        siemplify.LOGGER.info(f"Started checking resubmission day for entity: {entity_original_identifier}")

        try:
            hash_data = manager.get_hash_data(file_hash=get_entity_original_identifier(entity), show_entity_status=True)

            if unix_now() - convert_days_to_milliseconds(resubmit_days) > hash_data.last_analysis_date * 1000:
                entities_to_resubmit.append(entity)
            else:
                entities_data[entity_original_identifier] = hash_data.to_json()

            siemplify.LOGGER.info(f"Finished checking resubmission day for entity {entity_original_identifier}")

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities_statuses[entity_original_identifier] = {"execution_status": str(e)}
            siemplify.LOGGER.error(f"An error occurred on entity {entity_original_identifier}")
            siemplify.LOGGER.exception(e)

    return entities_to_resubmit, entities_data, failed_entities_statuses


def resubmit_hashes(siemplify, manager, suitable_entities, failed_entities_statuses):
    """
    Resubmit hashes
    :param siemplify: {siemplify} Siemplify object
    :param manager: {VirusTotalManager} VirusTotalManager manager object
    :param suitable_entities: {list} list of siemplify entities
    :param failed_entities_statuses: {dict} failed entity identifiers with statuses
    :return: {tuple} output_message, result_value, status, failed_entities_statuses
    """
    failed_entities, successful_entities, result_value = [], [], {}
    output_message = ""
    status = EXECUTION_STATE_INPROGRESS

    for entity in suitable_entities:
        siemplify.LOGGER.info("Started entity submission for analyse: {}".format(get_entity_original_identifier(entity)))

        try:
            analysis_id = manager.submit_hash_for_analysis(hash=get_entity_original_identifier(entity),
                                                           show_entity_status=True)

            # Fill json with every entity data
            result_value[get_entity_original_identifier(entity)] = analysis_id
            successful_entities.append(entity)
            siemplify.LOGGER.info("Finished entity submission for analyse: {}".format(get_entity_original_identifier(entity)))

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities.append(get_entity_original_identifier(entity))
            failed_entities_statuses[get_entity_original_identifier(entity)] = {"execution_status": str(e)}
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(e)

    if successful_entities:
        output_message += "Successfully submitted the following hashes for analysis: \n {} \n" \
            .format(", ".join([get_entity_original_identifier(entity) for entity in successful_entities]))
        result_value = json.dumps(result_value)

    if failed_entities:
        output_message += "Action wasn't able to submitted the following hashes for analysis: \n {} \n" \
            .format(", ".join(failed_entities))

    if not successful_entities:
        output_message = "No hashes were submitted for analysis"
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status, failed_entities_statuses


def check_analysis_status(siemplify, manager, task_analysis, failed_entities_statuses):
    """
    Check analysis status
    :param siemplify: {siemplify} Siemplify object
    :param manager: {VirusTotalManager} VirusTotalManager manager object
    :param task_analysis: {dict} entity identifiers with analyse ids
    :param failed_entities_statuses: {dict} failed entities with statuses
    :return: {tuple} output_message, result_value, failed_entities_statuses
    """
    result_value = {}

    for entity, analysis_id in task_analysis.items():
        try:
            if COMPLETED != manager.check_analysis_status(analysis_id, show_entity_status=True):
                result_value[entity] = analysis_id
        except Exception as e:
            failed_entities_statuses[entity] = {"execution_status": str(e)}
            siemplify.LOGGER.error("An error occurred when checking status for hash {}".format(entity))
            siemplify.LOGGER.exception(e)

    output_message = "Waiting for action to complete analyse for the following hashes: \n{}" \
        .format(",".join(result_value.keys()))

    return output_message, result_value, failed_entities_statuses


def finish_operation(siemplify, manager, suitable_entities, threshold, percentage_threshold, whitelists,
                     retrieve_comments, retrieve_sigma_analysis, create_insight, only_suspicious_insight, limit,
                     entities_existing_data, failed_entities_statuses, retrieve_sandbox_analysis, sandboxes,
                     widget_theme, fetch_widget):
    successful_entities = []
    failed_entities = []
    invalid_entities = []
    comments = []
    not_found_engines = set()
    global_is_risky = False
    sigma_analysis = None
    json_results = failed_entities_statuses
    output_message = ""
    result_value = True

    for entity in suitable_entities:
        siemplify.LOGGER.info(f"Started processing entity: {get_entity_original_identifier(entity)}")
        is_risky = False
        sandboxes_data = {}

        try:
            if len(get_entity_original_identifier(entity)) not in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]:
                raise VirusTotalInvalidFormat

            if entities_existing_data.get(get_entity_original_identifier(entity)):
                parser = VirusTotalParser()
                hash_data = parser.build_hash_object(
                    {"data": entities_existing_data.get(get_entity_original_identifier(entity))},
                    'file', get_entity_original_identifier(entity)
                )
            else:
                hash_data = manager.get_hash_data(file_hash=get_entity_original_identifier(entity),
                                                  show_entity_status=True)

            hash_data.set_supported_engines(whitelists)
            not_found_engines.update(set(hash_data.invalid_engines))

            if retrieve_comments:
                comments = manager.get_comments(url_type="files", entity=get_entity_original_identifier(entity),
                                                limit=limit, show_entity_status=True)

            if retrieve_sandbox_analysis:
                for sandbox in sandboxes:
                    try:
                        sandboxes_data[sandbox] = manager.get_sandbox_data(get_entity_original_identifier(entity),
                                                                           sandbox, show_entity_status=True)
                    except Exception as err:
                        siemplify.LOGGER.error(f"An error occurred on sandbox data retrieve for "
                                               f"{get_entity_original_identifier(entity)}")
                        siemplify.LOGGER.exception(err)
                        sandboxes_data[sandbox] = None

            widget_link = manager.get_widget_link(get_entity_original_identifier(entity), show_entity_status=True,
                                                  theme_colors=WIDGET_THEME_MAPPING.get(widget_theme)) \
                if fetch_widget else None
            hash_data.widget_link = widget_link

            try:
                if retrieve_sigma_analysis:
                    sigma_analysis = manager.get_sigma_analysis(file_hash=entity)
            except Exception as err:
                siemplify.LOGGER.error(f"An error occurred on sigma analysis retrieve for "
                                       f"{get_entity_original_identifier(entity)}")
                siemplify.LOGGER.exception(err)

            if threshold:
                if hash_data.threshold >= int(threshold):
                    is_risky = True
                    global_is_risky = True
                    entity.is_suspicious = True
            else:
                if int(hash_data.percentage_threshold) >= percentage_threshold:
                    is_risky = True
                    global_is_risky = True
                    entity.is_suspicious = True

            # Enrich entity
            entity.additional_properties.update(hash_data.to_enrichment_data(widget_link=widget_link))
            # Add case wall table for entity
            siemplify.result.add_data_table(title="{}".format(get_entity_original_identifier(entity)),
                                            data_table=construct_csv(hash_data.to_table()))
            # Fill json with every entity data
            json_results[get_entity_original_identifier(entity)] = hash_data.to_json(comments=comments,
                                                                                     widget_link=widget_link)
            json_results[get_entity_original_identifier(entity)].update({"execution_status": "success"})

            if sandboxes_data:
                json_results[get_entity_original_identifier(entity)].update({
                    "sandboxes_analysis": {key: value.to_json() if value else None
                                           for key, value in sandboxes_data.items()}
                })

            # Create case wall table for comments
            if comments:
                siemplify.result.add_data_table(
                    title=COMMENTS_TABLE_TITLE.format(get_entity_original_identifier(entity)),
                    data_table=construct_csv([comment.to_table() for comment in comments]))
            if sigma_analysis and sigma_analysis.rule_matches:
                siemplify.result.add_data_table(
                    title=SIGMA_ANALYSIS_TITLE.format(get_entity_original_identifier(entity)),
                    data_table=construct_csv(sigma_analysis.to_table()))

            if hash_data.report_link:
                siemplify.result.add_entity_link(REPORT_LINK_TITLE, hash_data.report_link)

            if create_insight:
                if not only_suspicious_insight or (only_suspicious_insight and is_risky):
                    siemplify.add_entity_insight(entity, hash_data.to_insight(threshold or f"{percentage_threshold}%"),
                                                 triggered_by=INTEGRATION_NAME)

            entity.is_enriched = True
            successful_entities.append(entity)

        except VirusTotalInvalidFormat:
            invalid_entities.append(get_entity_original_identifier(entity))
            json_results[get_entity_original_identifier(entity)] = {"execution_status": "invalid hash format"}

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities.append(get_entity_original_identifier(entity))
            json_results[get_entity_original_identifier(entity)] = {"execution_status": str(e)}
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(e)

        siemplify.LOGGER.info("Finished processing entity {}".format(get_entity_original_identifier(entity)))

    if successful_entities:
        output_message += "Successfully enriched the following hashes using {}: \n {} \n" \
            .format(PROVIDER_NAME,
                    ', '.join([get_entity_original_identifier(entity) for entity in successful_entities]))
        siemplify.update_entities(successful_entities)

    if failed_entities:
        output_message += "Action wasn't able to enrich the following hashes using {}: \n {} \n" \
            .format(PROVIDER_NAME, ', '.join(failed_entities))

    if invalid_entities:
        output_message += "The following hashes have invalid format: \n {} \n" \
            .format(', '.join(invalid_entities))

    if not_found_engines:
        output_message += "The following whitelisted engines were not found in {}: \n{} \n" \
            .format(PROVIDER_NAME, ', '.join(not_found_engines))

    if not successful_entities:
        output_message = "No hashes were enriched"
        result_value = False

    # Main JSON result
    if json_results:
        siemplify.result.add_result_json({
            "results": convert_dict_to_json_result_dict(json_results),
            "is_risky": global_is_risky
        })

    return output_message, result_value, EXECUTION_STATE_COMPLETED


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_HASH_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # Parameters
    threshold = extract_action_param(siemplify, param_name="Engine Threshold", is_mandatory=False, input_type=int,
                                     print_value=True)
    percentage_threshold = extract_action_param(siemplify, param_name="Engine Percentage Threshold", is_mandatory=False,
                                                input_type=int, print_value=True)
    whitelist_str = extract_action_param(siemplify, param_name="Engine Whitelist", is_mandatory=False, print_value=True)
    retrieve_comments = extract_action_param(siemplify, param_name="Retrieve Comments", is_mandatory=False,
                                             input_type=bool)
    retrieve_sigma_analysis = extract_action_param(siemplify, param_name="Retrieve Sigma Analysis", is_mandatory=False,
                                                   input_type=bool)
    create_insight = extract_action_param(siemplify, param_name="Create Insight", is_mandatory=False,
                                          input_type=bool, default_value=True)
    only_suspicious_insight = extract_action_param(siemplify, param_name="Only Suspicious Entity Insight",
                                                   is_mandatory=False, input_type=bool, default_value=False)
    max_returned_comments = extract_action_param(siemplify, param_name="Max Comments To Return", is_mandatory=False,
                                                 input_type=int, default_value=DEFAULT_LIMIT)
    resubmit_hash = extract_action_param(siemplify, param_name="Resubmit Hash", is_mandatory=False, input_type=bool, default_value=False)
    resubmit_days = extract_action_param(siemplify, param_name="Resubmit After (Days)", input_type=int,
                                         default_value=DEFAULT_RESUBMIT_DAYS)
    sandbox_str = extract_action_param(siemplify, param_name="Sandbox", default_value=DEFAULT_SANDBOX, print_value=True)
    retrieve_sandbox_analysis = extract_action_param(siemplify, param_name="Retrieve Sandbox Analysis", input_type=bool,
                                                     print_value=True)
    widget_theme = extract_action_param(siemplify, param_name="Widget Theme", print_value=True)
    fetch_widget = extract_action_param(siemplify, param_name="Fetch Widget", input_type=bool, default_value=True,
                                        print_value=True)

    additional_data = json.loads(extract_action_param(siemplify, param_name="additional_data", default_value="{}"))
    whitelists = [item.strip() for item in whitelist_str.split(',') if item] if whitelist_str else []
    sandboxes = [item.strip() for item in sandbox_str.split(',') if item] if sandbox_str else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    output_message = ""
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    initial_suitable_entity_identifiers = additional_data.get("initial_suitable_entity_identifiers", [])

    if is_first_run:
        suitable_entities = [entity for entity in siemplify.target_entities
                             if entity.entity_type == EntityTypes.FILEHASH]
    else:
        suitable_entities = [entity for entity in siemplify.target_entities
                             if entity.identifier in initial_suitable_entity_identifiers]

    valid_suitable_entities = [entity for entity in suitable_entities
                               if len(get_entity_original_identifier(entity)) in [MD5_LENGTH, SHA1_LENGTH, SHA256_LENGTH]]

    try:
        if not threshold and not percentage_threshold:
            raise Exception(f"either \"Engine Threshold\" or \"Engine Percentage Threshold\" should be provided.")

        if percentage_threshold and (percentage_threshold > 100 or percentage_threshold < 0):
            raise Exception(f"value for the parameter \"Engine Percentage Threshold\" is invalid. Please check it. "
                  f"The value should be in range from 0 to 100")

        if resubmit_days < 0:
            raise Exception(f"Invalid value was provided for \"Resubmit After (Days)\": {resubmit_days}. "
                            f"Positive number or 0 should be provided.")

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)
        finalize = False
        entities_existing_data = additional_data.get("entities_existing_data", {})
        failed_entities_statuses = additional_data.get("failed_entities_statuses", {})

        if resubmit_hash:
            if is_first_run:
                if resubmit_days > 0:
                    entities_to_resubmit, entities_existing_data, failed_entities_statuses = check_resubmission_day(
                        siemplify, manager, valid_suitable_entities, resubmit_days
                    )
                    output_message, result_value, status, failed_entities_statuses = resubmit_hashes(
                        siemplify=siemplify, manager=manager, suitable_entities=entities_to_resubmit,
                        failed_entities_statuses=failed_entities_statuses
                    )
                else:
                    output_message, result_value, status, failed_entities_statuses = resubmit_hashes(
                        siemplify=siemplify, manager=manager, suitable_entities=valid_suitable_entities,
                        failed_entities_statuses=failed_entities_statuses
                    )

            task_analysis_json = json.loads(result_value) if result_value else additional_data.get("entities_analysis", {})

            output_message, result_value, failed_entities_statuses = check_analysis_status(
                siemplify=siemplify, manager=manager, task_analysis=task_analysis_json,
                failed_entities_statuses=failed_entities_statuses
            )

            # if not remained analysis, we can finalize the action
            if not result_value:
                finalize = True
            else:
                status = EXECUTION_STATE_INPROGRESS
                result_value = json.dumps({
                    "entities_analysis": result_value,
                    "entities_existing_data": entities_existing_data,
                    "failed_entities_statuses": failed_entities_statuses,
                    "initial_suitable_entity_identifiers": [entity.identifier for entity in suitable_entities]
                })
        else:
            finalize = True

        if finalize:
            output_message, result_value, status = finish_operation(
                siemplify, manager, suitable_entities, threshold, percentage_threshold, whitelists,
                retrieve_comments, retrieve_sigma_analysis, create_insight, only_suspicious_insight,
                max_returned_comments, entities_existing_data, failed_entities_statuses, retrieve_sandbox_analysis,
                sandboxes, widget_theme, fetch_widget
            )

    except Exception as err:
        output_message = "Error executing action \"Enrich Hash\". Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)

