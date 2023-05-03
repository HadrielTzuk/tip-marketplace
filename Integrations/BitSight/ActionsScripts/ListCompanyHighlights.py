from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from BitSightManager import BitSightManager
from utils import validate_positive_integer, get_timestamps
from constants import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    LIST_COMPANY_HIGHLIGHTS_SCRIPT_NAME,
    DEFAULT_HIGHLIGHTS_LIMIT,
    TIME_FORMAT
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_COMPANY_HIGHLIGHTS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key",
                                          is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    company_name = extract_action_param(siemplify, param_name="Company Name", is_mandatory=True, print_value=True)
    time_frame = extract_action_param(siemplify, param_name="Time Frame", print_value=True)
    start_time = extract_action_param(siemplify, param_name="Start Time", print_value=True)
    end_time = extract_action_param(siemplify, param_name="End Time", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Highlights To Return", input_type=int,
                                 default_value=DEFAULT_HIGHLIGHTS_LIMIT, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    json_results = []
    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f"No highlights were found for the \"{company_name}\" company in {INTEGRATION_DISPLAY_NAME}"

    try:
        validate_positive_integer(
            number=limit,
            err_msg="Max Highlights To Return should be greater than zero."
        )

        manager = BitSightManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                  siemplify_logger=siemplify.LOGGER)

        company = next((item for item in manager.get_companies() if item.name == company_name), None)

        if not company:
            raise Exception(f"company \"{company_name}\" wasn't found in {INTEGRATION_DISPLAY_NAME}. "
                            f"Please check the spelling.")

        start_time, end_time = get_timestamps(range_string=time_frame, start_time_string=start_time,
                                              end_time_string=end_time)

        highlights = manager.get_company_highlights(company_id=company.guid, start_time=start_time, end_time=end_time,
                                                    limit=limit)

        if highlights:
            json_results = [highlight.to_json() for highlight in highlights]
            output_message = f"Successfully returned information about the \"{company_name}\" company highlights " \
                             f"in {INTEGRATION_DISPLAY_NAME}"

        siemplify.result.add_result_json(json_results)

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(f"General error performing action {LIST_COMPANY_HIGHLIGHTS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action \"{LIST_COMPANY_HIGHLIGHTS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
