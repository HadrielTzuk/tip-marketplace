from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from BitSightManager import BitSightManager
from constants import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    GET_COMPANY_DETAILS_SCRIPT_NAME
)

TABLE_NAME = "Company \"{}\" Details"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_COMPANY_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key",
                                          is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    company_name = extract_action_param(siemplify, param_name="Company Name", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = BitSightManager(api_root=api_root, api_key=api_key,
                                  verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        company = next((item for item in manager.get_companies() if item.name == company_name), None)

        if not company:
            raise Exception(f"company \"{company_name}\" wasn't found in {INTEGRATION_DISPLAY_NAME}. "
                            f"Please check the spelling.")

        company_details = manager.get_company_details(company_id=company.guid)
        company_details.rating = company.rating

        siemplify.result.add_data_table(TABLE_NAME.format(company_name), construct_csv([company_details.to_csv()]))
        siemplify.result.add_result_json(company_details.to_json())
        siemplify.result.add_link("URL", company_details.display_url)

        output_message = f"Successfully returned information about the \"{company_name}\" company " \
                         f"in {INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(f"General error performing action {GET_COMPANY_DETAILS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action \"{GET_COMPANY_DETAILS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
