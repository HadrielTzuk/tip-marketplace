from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from BMCRemedyITSMManager import BMCRemedyITSMManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, DELETE_RECORD_SCRIPT_NAME
from BMCRemedyITSMExceptions import BMCRemedyITSMNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DELETE_RECORD_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # action parameters
    record_type = extract_action_param(siemplify, param_name="Record Type", is_mandatory=True, print_value=True)
    record_id = extract_action_param(siemplify, param_name="Record ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    manager = None
    output_message = ""

    try:
        manager = BMCRemedyITSMManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                       siemplify_logger=siemplify.LOGGER)

        manager.delete_record(record_type, record_id)
        output_message = f"Successfully deleted {record_type} record with ID {record_id} in {INTEGRATION_DISPLAY_NAME}."

    except BMCRemedyITSMNotFoundException:
        output_message = f"{record_type} Record with ID {record_id} doesn't exist in {INTEGRATION_DISPLAY_NAME}."
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {DELETE_RECORD_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action {DELETE_RECORD_SCRIPT_NAME}. Reason: {e}"

    finally:
        try:
            if manager:
                siemplify.LOGGER.info(f"Logging out from {INTEGRATION_DISPLAY_NAME}..")
                manager.logout()
                siemplify.LOGGER.info(f"Successfully logged out from {INTEGRATION_DISPLAY_NAME}")
        except Exception as error:
            siemplify.LOGGER.error(f"Logging out failed. Error: {error}")
            siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
