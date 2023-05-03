import json
from SiemplifyUtils import output_handler, convert_unixtime_to_datetime
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from GoogleChronicleManager import GoogleChronicleManager
from consts import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    EXECUTE_UDM_QUERY_SCRIPT_NAME,
    UDM_QUERY_EVENTS_DEFAULT_LIMIT,
    UDM_QUERY_EVENTS_MAX_LIMIT
)
import utils
from exceptions import GoogleChronicleAPILimitError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_UDM_QUERY_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # integration configuration
    creds = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="User's Service Account",
        is_mandatory=True
    )
    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="API Root",
        is_mandatory=True,
        print_value=True
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool,
        print_value=True
    )

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(e)
        siemplify.end(
            "Unable to parse credentials as JSON. Please validate creds.",
            False,
            EXECUTION_STATE_FAILED
        )

    # action parameters
    query = extract_action_param(
        siemplify,
        param_name="Query",
        is_mandatory=True,
        print_value=True
    )

    time_frame = extract_action_param(
        siemplify,
        param_name="Time Frame",
        print_value=True
    )

    start_time = extract_action_param(
        siemplify,
        param_name="Start Time",
        print_value=True
    )

    end_time = extract_action_param(
        siemplify,
        param_name="End Time",
        print_value=True
    )

    limit = extract_action_param(
        siemplify,
        param_name="Max Results To Return",
        input_type=int,
        print_value=True,
        default_value=UDM_QUERY_EVENTS_DEFAULT_LIMIT
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_FAILED

    try:
        if limit < 1:
            raise Exception(
                "Max Results To Return should be greater than zero."
            )

        if limit > UDM_QUERY_EVENTS_MAX_LIMIT:
            raise Exception(
                f"Max Results To Return should be lower than "
                f"{UDM_QUERY_EVENTS_MAX_LIMIT}."
            )

        alert_start_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("StartTime"))
        )
        alert_end_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("EndTime"))
        )

        start_time, end_time = utils.get_timestamps(
            range_string=time_frame,
            start_time_string=start_time,
            end_time_string=end_time,
            alert_start_time=alert_start_time,
            alert_end_time=alert_end_time
        )

        manager = GoogleChronicleManager(
            api_root=api_root,
            verify_ssl=verify_ssl,
            siemplify_logger=siemplify.LOGGER,
            **creds
        )

        events = manager.get_events_by_udm_query(
            query, start_time, end_time, limit
        )

        status = EXECUTION_STATE_COMPLETED
        result_value = True

        if events:
            siemplify.result.add_result_json({
                "events": [event.to_json() for event in events]
            })
            output_message = f"Successfully returned results for the query " \
                             f"\"{query}\" in {INTEGRATION_DISPLAY_NAME}."
        else:
            output_message = f"No results were found for the query " \
                             f"\"{query}\" in {INTEGRATION_DISPLAY_NAME}."

    except GoogleChronicleAPILimitError:
        output_message = f"Error executing action " \
                         f"\"{EXECUTE_UDM_QUERY_SCRIPT_NAME}\". Reason: " \
                         f"you've reached a rate limit. Please wait for " \
                         f"several minutes and try again."

    except Exception as e:
        siemplify.LOGGER.error(
            f"General error performing action {EXECUTE_UDM_QUERY_SCRIPT_NAME}"
        )
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action " \
                         f"{EXECUTE_UDM_QUERY_SCRIPT_NAME}. Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
