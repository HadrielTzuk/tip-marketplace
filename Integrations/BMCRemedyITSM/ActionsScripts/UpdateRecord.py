import json
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from BMCRemedyITSMManager import BMCRemedyITSMManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_RECORD_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_RECORD_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    record_type = extract_action_param(siemplify, param_name="Record Type", is_mandatory=True, print_value=True)
    record_id = extract_action_param(siemplify, param_name="Record ID", is_mandatory=True, print_value=True)
    record_payload = extract_action_param(siemplify, param_name="Record Payload", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    manager = None
    output_message = ""

    try:
        try:
            record_payload = json.loads(record_payload) if record_payload else {}
        except Exception:
            raise Exception("Invalid JSON payload provided in the parameter \"Record Payload\". Please check the "
                            "structure.")

        manager = BMCRemedyITSMManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                       siemplify_logger=siemplify.LOGGER)

        manager.update_record(record_id=record_id, record_type=record_type, record_payload=record_payload)
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully updated {record_type} record with {record_id} in {INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UPDATE_RECORD_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action {UPDATE_RECORD_SCRIPT_NAME}. Reason: {e}"

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
