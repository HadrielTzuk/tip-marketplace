import json
import sys

from ScriptResult import (
    EXECUTION_STATE_COMPLETED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_INPROGRESS,
)
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, unix_now
from TIPCommon import (
    extract_configuration_param,
    extract_action_param,
    construct_csv,
)
from UtilsManager import (
    get_entity_original_identifier,
    prepare_entity_for_manager,
    convert_days_to_milliseconds,
)
from VirusTotalManager import VirusTotalManager
from VirusTotalParser import VirusTotalParser
from constants import (
    PROVIDER_NAME,
    INTEGRATION_NAME,
    ENRICH_URL_SCRIPT_NAME,
    COMPLETED,
    WIDGET_THEME_MAPPING,
)
from exceptions import ForceRaiseException, VirusTotalNotFoundException


def check_resubmission_day(siemplify, manager, suitable_entities, resubmit_days):
    entities_to_resubmit = []
    entities_data = {}
    failed_entities_statuses = {}

    for entity in suitable_entities:
        entity_original_identifier = get_entity_original_identifier(entity)
        siemplify.LOGGER.info(
            f"Started checking resubmission day for entity: {entity_original_identifier}"
        )

        try:
            url_data = manager.get_url_data(
                url=prepare_entity_for_manager(entity), show_entity_status=True
            )

            if (
                unix_now() - convert_days_to_milliseconds(resubmit_days)
                > url_data.last_analysis_date * 1000
            ):
                entities_to_resubmit.append(entity)
            else:
                entities_data[entity_original_identifier] = url_data.to_json()

            siemplify.LOGGER.info(
                f"Finished checking resubmission day for entity {entity_original_identifier}"
            )

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities_statuses[entity_original_identifier] = {
                "execution_status": str(e)
            }
            siemplify.LOGGER.error(
                f"An error occurred on entity {entity_original_identifier}"
            )
            siemplify.LOGGER.exception(e)

    return entities_to_resubmit, entities_data, failed_entities_statuses


def check_entity_data(siemplify, manager, suitable_entities):
    entities_to_resubmit = []
    entities_data = {}
    failed_entities_statuses = {}

    for entity in suitable_entities:
        entity_original_identifier = get_entity_original_identifier(entity)
        siemplify.LOGGER.info(
            f"Started checking data for entity: {entity_original_identifier}"
        )

        try:
            url_data = manager.get_url_data(
                url=prepare_entity_for_manager(entity), show_entity_status=True
            )

            entities_data[entity_original_identifier] = url_data.to_json()

            siemplify.LOGGER.info(
                f"Finished checking data for entity {entity_original_identifier}"
            )

        except VirusTotalNotFoundException:
            siemplify.LOGGER.error(
                f"Data not found for entity {entity_original_identifier}"
            )
            entities_to_resubmit.append(entity)
        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities_statuses[entity_original_identifier] = {
                "execution_status": str(e)
            }
            siemplify.LOGGER.error(
                f"An error occurred on entity {entity_original_identifier}"
            )
            siemplify.LOGGER.exception(e)

    return entities_to_resubmit, entities_data, failed_entities_statuses


def start_operation(siemplify, manager, suitable_entities, failed_entities_statuses):
    failed_entities, successful_entities, result_value = [], [], {}
    output_message = ""
    status = EXECUTION_STATE_INPROGRESS

    for entity in suitable_entities:
        siemplify.LOGGER.info(
            "Started processing entity {}".format(
                get_entity_original_identifier(entity)
            )
        )

        try:
            analysis_id = manager.submit_url_for_analysis(
                url=get_entity_original_identifier(entity), show_entity_status=True
            )

            # Fill json with every entity data
            result_value[get_entity_original_identifier(entity)] = analysis_id
            successful_entities.append(entity)
            siemplify.LOGGER.info(
                "Finished processing entity {}".format(
                    get_entity_original_identifier(entity)
                )
            )

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise

            failed_entities.append(get_entity_original_identifier(entity))
            failed_entities_statuses[get_entity_original_identifier(entity)] = {
                "execution_status": str(e)
            }
            siemplify.LOGGER.error(
                "An error occurred on entity {}".format(
                    get_entity_original_identifier(entity)
                )
            )
            siemplify.LOGGER.exception(e)

    if successful_entities:
        output_message += (
            "Successfully submitted the following URLs for analysis: \n {} \n".format(
                ", ".join(
                    [
                        get_entity_original_identifier(entity)
                        for entity in successful_entities
                    ]
                )
            )
        )
        result_value = json.dumps(result_value)

    if failed_entities:
        output_message += "Action wasn't able to submitted the following URLs for analysis: \n {} \n".format(
            ", ".join(failed_entities)
        )

    if not successful_entities:
        output_message = "No URLs were submitted for analysis"
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status, failed_entities_statuses


def query_operation_status(siemplify, manager, task_analysis, failed_entities_statuses):
    result_value = {}

    for entity, analysis_id in task_analysis.items():
        try:
            if COMPLETED != manager.check_analysis_status(
                analysis_id, show_entity_status=True
            ):
                result_value[entity] = analysis_id
        except Exception as e:
            failed_entities_statuses[entity] = {"execution_status": str(e)}
            siemplify.LOGGER.error(
                "An error occurred when checking status for url {}".format(entity)
            )
            siemplify.LOGGER.exception(e)

    return (
        "Waiting for action to retrieve results for the following URLs:\n{}".format(
            ",".join(result_value.keys())
        ),
        result_value,
        failed_entities_statuses,
    )


def finish_operation(
    siemplify,
    manager,
    suitable_entities,
    threshold,
    percentage_threshold,
    entities_existing_data,
    failed_entities_statuses,
    widget_theme,
    fetch_widget,
):
    global_is_risky = False
    successful_entities = []
    failed_entities = []
    not_found_engines = set()
    json_results = failed_entities_statuses
    result_value = True
    comments = []
    output_message = ""

    retrieve_comments = extract_action_param(
        siemplify, param_name="Retrieve Comments", is_mandatory=False, input_type=bool
    )
    max_returned_comments = extract_action_param(
        siemplify,
        param_name="Max Comments To Return",
        is_mandatory=False,
        input_type=int,
        default_value=10,
    )
    only_suspicious_insight = extract_action_param(
        siemplify,
        param_name="Only Suspicious Entity Insight",
        is_mandatory=False,
        input_type=bool,
        default_value=False,
    )
    create_insight = extract_action_param(
        siemplify,
        param_name="Create Insight",
        is_mandatory=False,
        input_type=bool,
        default_value=True,
    )
    whitelist_str = extract_action_param(
        siemplify, param_name="Engine Whitelist", is_mandatory=False, print_value=True
    )
    whitelists = (
        [item.strip() for item in whitelist_str.split(",") if item]
        if whitelist_str
        else []
    )

    for entity in suitable_entities:
        siemplify.LOGGER.info(
            "Started processing entity: {}".format(
                get_entity_original_identifier(entity)
            )
        )

        try:
            identifier = prepare_entity_for_manager(entity)
            is_risky = False

            if entities_existing_data.get(get_entity_original_identifier(entity)):
                parser = VirusTotalParser()
                url_data = parser.build_url_object(
                    {
                        "data": entities_existing_data.get(
                            get_entity_original_identifier(entity)
                        )
                    },
                    "url",
                    identifier,
                )
            else:
                url_data = manager.get_url_data(url=identifier, show_entity_status=True)

            url_data.set_supported_engines(whitelists)
            not_found_engines.update(set(url_data.invalid_engines))
            if retrieve_comments:
                comments = manager.get_comments(
                    url_type="urls",
                    entity=url_data.entity_id,
                    limit=max_returned_comments,
                    show_entity_status=True,
                )

            widget_link, widget_html = (
                manager.get_widget(
                    get_entity_original_identifier(entity),
                    show_entity_status=True,
                    theme_colors=WIDGET_THEME_MAPPING.get(widget_theme),
                )
                if fetch_widget
                else (None, None)
            )
            url_data.widget_link = widget_link
            url_data.widget_html = widget_html

            if threshold:
                if url_data.threshold >= int(threshold):
                    is_risky = True
                    global_is_risky = True
                    entity.is_suspicious = True
            else:
                if int(url_data.percentage_threshold) >= percentage_threshold:
                    is_risky = True
                    global_is_risky = True
                    entity.is_suspicious = True

            # Enrich entity
            entity.additional_properties.update(url_data.to_enrichment_data())
            # Add case wall table for entity
            siemplify.result.add_data_table(
                title="{}".format(entity.identifier),
                data_table=construct_csv(url_data.to_table()),
            )
            # Fill json with every entity data
            json_results[get_entity_original_identifier(entity)] = url_data.to_json(
                comments=comments, widget_link=widget_link
            )
            json_results[get_entity_original_identifier(entity)].update(
                {"execution_status": "success"}
            )
            # Create case wall table for comments
            if comments:
                comments_table = construct_csv(
                    [comment.to_table() for comment in comments]
                )
                siemplify.result.add_data_table(
                    title="Comments: {}".format(get_entity_original_identifier(entity)),
                    data_table=comments_table,
                )

            if url_data.report_link:
                siemplify.result.add_entity_link(
                    entity.identifier, url_data.report_link
                )

            if create_insight:
                if not only_suspicious_insight or (
                    only_suspicious_insight and is_risky
                ):
                    siemplify.add_entity_insight(
                        entity,
                        url_data.to_insight(threshold or f"{percentage_threshold}%"),
                        triggered_by=INTEGRATION_NAME,
                    )

            entity.is_enriched = True
            successful_entities.append(entity)
            siemplify.LOGGER.info(
                "Finished processing entity {0}".format(
                    get_entity_original_identifier(entity)
                )
            )

        except Exception as e:
            if isinstance(e, ForceRaiseException):
                raise
            failed_entities.append(get_entity_original_identifier(entity))
            json_results[get_entity_original_identifier(entity)] = {
                "execution_status": str(e)
            }
            siemplify.LOGGER.error(
                "An error occurred on entity {0}".format(
                    get_entity_original_identifier(entity)
                )
            )
            siemplify.LOGGER.exception(e)

    if successful_entities:
        output_message += (
            "Successfully enriched the following URLs using  {}: \n {} \n".format(
                PROVIDER_NAME,
                ", ".join(
                    [
                        get_entity_original_identifier(entity)
                        for entity in successful_entities
                    ]
                ),
            )
        )
        siemplify.update_entities(successful_entities)

    if failed_entities:
        output_message += (
            "Action wasn't able to enrich the following URLs using {}: \n {} \n".format(
                PROVIDER_NAME, ", ".join(failed_entities)
            )
        )

    if not_found_engines:
        output_message += (
            "The following whitelisted engines were not found in {}: \n{} \n".format(
                PROVIDER_NAME, ", ".join(list(not_found_engines))
            )
        )

    if not successful_entities:
        output_message = "No URLs were enriched"
        result_value = False

    # Main JSON result
    if json_results:
        result = {
            "results": convert_dict_to_json_result_dict(json_results),
            "is_risky": global_is_risky,
        }
        siemplify.result.add_result_json(result)

    return output_message, result_value, EXECUTION_STATE_COMPLETED


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_URL_SCRIPT_NAME

    mode = "Main" if is_first_run else "Get Report"
    siemplify.LOGGER.info(
        "----------------- {} - Param Init -----------------".format(mode)
    )

    api_key = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="API Key"
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        default_value=True,
        input_type=bool,
    )

    # action parameters
    resubmit_url = extract_action_param(
        siemplify,
        param_name="Resubmit URL",
        default_value=False,
        is_mandatory=False,
        print_value=True,
        input_type=bool,
    )
    threshold = extract_action_param(
        siemplify,
        param_name="Engine Threshold",
        is_mandatory=False,
        input_type=int,
        print_value=True,
    )
    percentage_threshold = extract_action_param(
        siemplify,
        param_name="Engine Percentage Threshold",
        is_mandatory=False,
        input_type=int,
        print_value=True,
    )
    resubmit_days = extract_action_param(
        siemplify,
        param_name="Resubmit After (Days)",
        input_type=int,
        default_value=30,
        print_value=True,
    )
    widget_theme = extract_action_param(
        siemplify, param_name="Widget Theme", print_value=True
    )
    fetch_widget = extract_action_param(
        siemplify,
        param_name="Fetch Widget",
        input_type=bool,
        default_value=True,
        print_value=True,
    )

    additional_data = json.loads(
        extract_action_param(
            siemplify, param_name="additional_data", default_value="{}"
        )
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value, output_message = False, ""
    initial_suitable_entity_identifiers = additional_data.get(
        "initial_suitable_entity_identifiers", []
    )

    if is_first_run:
        suitable_entities = [
            entity
            for entity in siemplify.target_entities
            if entity.entity_type == EntityTypes.URL
        ]
    else:
        suitable_entities = [
            entity
            for entity in siemplify.target_entities
            if entity.identifier in initial_suitable_entity_identifiers
        ]

    try:
        if not threshold and not percentage_threshold:
            raise Exception(
                f'either "Engine Threshold" or "Engine Percentage Threshold" should be provided.'
            )

        if percentage_threshold and (
            percentage_threshold > 100 or percentage_threshold < 0
        ):
            raise Exception(
                f'value for the parameter "Engine Percentage Threshold" is invalid. Please check it. '
                f"The value should be in range from 0 to 100"
            )

        finalize = not resubmit_url
        entities_existing_data = additional_data.get("entities_existing_data", {})
        failed_entities_statuses = additional_data.get("failed_entities_statuses", {})
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        if resubmit_days < 0:
            raise Exception(
                f'Invalid value was provided for "Resubmit After (Days)": {resubmit_days}. '
                f"Positive number or 0 should be provided."
            )

        if is_first_run:
            if resubmit_url and resubmit_days > 0:
                (
                    entities_to_resubmit,
                    entities_existing_data,
                    failed_entities_statuses,
                ) = check_resubmission_day(
                    siemplify, manager, suitable_entities, resubmit_days
                )
                (
                    output_message,
                    result_value,
                    status,
                    failed_entities_statuses,
                ) = start_operation(
                    siemplify=siemplify,
                    manager=manager,
                    suitable_entities=entities_to_resubmit,
                    failed_entities_statuses=failed_entities_statuses,
                )
            elif resubmit_url:
                (
                    output_message,
                    result_value,
                    status,
                    failed_entities_statuses,
                ) = start_operation(
                    siemplify=siemplify,
                    manager=manager,
                    suitable_entities=suitable_entities,
                    failed_entities_statuses=failed_entities_statuses,
                )
            else:
                (
                    entities_to_resubmit,
                    entities_existing_data,
                    failed_entities_statuses,
                ) = check_entity_data(siemplify, manager, suitable_entities)

                (
                    output_message,
                    result_value,
                    status,
                    failed_entities_statuses,
                ) = start_operation(
                    siemplify=siemplify,
                    manager=manager,
                    suitable_entities=entities_to_resubmit,
                    failed_entities_statuses=failed_entities_statuses,
                )

        task_analysis_json = (
            json.loads(result_value)
            if result_value
            else additional_data.get("entities_analysis", {})
        )

        if task_analysis_json:
            (
                output_message,
                result_value,
                failed_entities_statuses,
            ) = query_operation_status(
                siemplify=siemplify,
                manager=manager,
                task_analysis=task_analysis_json,
                failed_entities_statuses=failed_entities_statuses,
            )

        # if not remained analysis, we can finalize the action
        if isinstance(result_value, bool) or len(result_value) == 0:
            finalize = True
        else:
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(
                {
                    "entities_analysis": result_value,
                    "entities_existing_data": entities_existing_data,
                    "failed_entities_statuses": failed_entities_statuses,
                    "initial_suitable_entity_identifiers": [
                        entity.identifier for entity in suitable_entities
                    ],
                }
            )

        if finalize:
            output_message, result_value, status = finish_operation(
                siemplify=siemplify,
                manager=manager,
                suitable_entities=suitable_entities,
                threshold=threshold,
                percentage_threshold=percentage_threshold,
                entities_existing_data=entities_existing_data,
                failed_entities_statuses=failed_entities_statuses,
                widget_theme=widget_theme,
                fetch_widget=fetch_widget,
            )

    except Exception as err:
        output_message = "Error executing action “Enrich URL”. Reason: {}".format(err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(
            status, result_value, output_message
        )
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
