from SiemplifyUtils import output_handler
from CofenseTriageManager import CofenseTriageManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    PRODUCT,
    EXECUTE_PLAYBOOK_ACTION
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_PLAYBOOK_ACTION
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
        is_mandatory=True, print_value=True
    )
    client_id = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
        is_mandatory=True, print_value=True
    )
    client_secret = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
        is_mandatory=True, remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL", is_mandatory=True,
        default_value=False, input_type=bool, print_value=True
    )

    report_id = extract_action_param(
        siemplify, param_name="Report ID", print_value=True, is_mandatory=True
    )
    playbook_name = extract_action_param(
        siemplify, param_name="Playbook Name", print_value=True, is_mandatory=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        manager = CofenseTriageManager(
            api_root=api_root, client_id=client_id, client_secret=client_secret,
            verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER
        )

        playbook = manager.get_playbook_by_name(
            name=playbook_name
        )

        if not playbook:
            raise Exception(f"playbook with name {playbook_name} is not found.")

        manager.get_report(
            report_id=report_id
        )

        manager.execute_playbook(
            playbook_id=playbook.identifier,
            report_id=report_id
        )
        output_message = f"Successfully executed playbook {playbook_name} on report {report_id} in {PRODUCT}."

    except Exception as e:
        output_message = f"Error executing action \"{EXECUTE_PLAYBOOK_ACTION}\". Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
