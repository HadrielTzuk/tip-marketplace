from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from DevoManager import DevoManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import DevoManagerErrorBadQueryException, DevoManagerErrorValidationException
from utils import get_start_end_timestamp
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    ADVANCED_QUERY_SCRIPT_NAME, TIME_FRAME_DEFAULT_VALUE, MAX_ROWS_TO_RETURN_DEFAULT_VALUE, CUSTOM_TIME_FRAME,
    TIME_FRAME_MAPPING, NOW, QUERY, FROM, TO, MODE, MODE_TYPE, JSON_MODE, LIMIT, MAX_ROWS_TO_RETURN_MINIMUM_VALUE
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {ADVANCED_QUERY_SCRIPT_NAME}"
    siemplify.LOGGER.info("=================== Main - Param Init ===================")

    # Integration configuration
    api_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API URL",
                                          is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Token",
                                            is_mandatory=False, print_value=False, remove_whitespaces=False)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Key",
                                          is_mandatory=False, print_value=False, remove_whitespaces=False)
    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Secret",
                                             is_mandatory=False, print_value=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL',
                                             input_type=bool,
                                             is_mandatory=True, default_value=True, print_value=True)

    # Action params
    query = extract_action_param(siemplify, param_name="Query", print_value=True, is_mandatory=True)
    time_frame = extract_action_param(siemplify, param_name="Time Frame", print_value=True, is_mandatory=False,
                                      default_value=TIME_FRAME_DEFAULT_VALUE)
    start_time = extract_action_param(siemplify, param_name="Start Time", print_value=True, is_mandatory=False)
    end_time = extract_action_param(siemplify, param_name="End Time", print_value=True, is_mandatory=False)

    result_value = False
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        max_rows_to_return = extract_action_param(siemplify, param_name="Max rows to return", print_value=True,
                                                  is_mandatory=False, input_type=int,
                                                  default_value=MAX_ROWS_TO_RETURN_DEFAULT_VALUE)

        if max_rows_to_return < MAX_ROWS_TO_RETURN_MINIMUM_VALUE:
            raise DevoManagerErrorValidationException("'Max Rows to Return' should be positive, non-zero number.")

        siemplify.LOGGER.info("Validating the provided time frame")
        if time_frame != CUSTOM_TIME_FRAME:
            time_frame_start = TIME_FRAME_MAPPING.get(time_frame)
            time_frame_end = NOW
        else:
            time_frame_start, time_frame_end = get_start_end_timestamp(start_time, end_time)
        siemplify.LOGGER.info("Successfully validated the provided time frame")

        manager = DevoManager(
            api_url=api_url,
            api_token=api_token,
            api_key=api_key,
            api_secret=api_secret,
            verify_ssl=verify_ssl,
            force_test_connectivity=False,
            siemplify=siemplify
        )

        # Query Parameters
        params = {
            QUERY: query,
            FROM: time_frame_start,
            TO: time_frame_end,
            MODE: {
                MODE_TYPE: JSON_MODE
            },
            LIMIT: max_rows_to_return
        }

        siemplify.LOGGER.info("Executing an advanced query based on the provided parameters")
        query_result = manager.run_advanced_query(params=params)
        siemplify.LOGGER.info("Successfully Executed an advanced query based on the provided parameters")

        if query_result.objects:
            result_value = True
            output_message = f"Successfully retrieved results for the provided query in {INTEGRATION_DISPLAY_NAME}"
            # JSON
            siemplify.result.add_result_json(query_result.to_json())
            # CSV
            siemplify.result.add_data_table(title='Advanced Query Results', data_table=construct_csv(
                [query_obj.to_csv() for query_obj in query_result.objects]))

        else:
            output_message = f"No results found for the provided query in {INTEGRATION_DISPLAY_NAME}"

        status = EXECUTION_STATE_COMPLETED

    except (DevoManagerErrorBadQueryException, DevoManagerErrorValidationException) as error:
        output_message = f"Error executing action 'Advanced Search'! Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    except Exception as error:
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} instance! Error is: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
