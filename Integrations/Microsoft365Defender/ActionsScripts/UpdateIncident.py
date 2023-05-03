from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from Microsoft365DefenderManager import Microsoft365DefenderManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_INCIDENT_SCRIPT_NAME, EMPTY_DROPDOWN_VALUE, \
    CLASSIFICATION_MAPPING, DETERMINATION_MAPPING


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_INCIDENT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant ID",
                                            is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    incident_id = extract_action_param(siemplify, param_name="Incident ID", is_mandatory=True, input_type=int,
                                       print_value=True)
    incident_status = extract_action_param(siemplify, param_name="Status", print_value=True)
    classification = extract_action_param(siemplify, param_name="Classification", print_value=True)
    determination = extract_action_param(siemplify, param_name="Determination", print_value=True)
    assign_to = extract_action_param(siemplify, param_name="Assign To", print_value=True)

    incident_status = incident_status if incident_status != EMPTY_DROPDOWN_VALUE else None
    classification = CLASSIFICATION_MAPPING.get(classification) if classification != EMPTY_DROPDOWN_VALUE else None
    determination = DETERMINATION_MAPPING.get(determination) if determination != EMPTY_DROPDOWN_VALUE else None

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        if all(value is None for value in [assign_to, incident_status, classification, determination]):
            raise Exception('at least one of the parameters should have a value provided.')

        manager = Microsoft365DefenderManager(api_root=api_root, tenant_id=tenant_id, client_id=client_id,
                                              client_secret=client_secret, verify_ssl=verify_ssl,
                                              siemplify=siemplify)
        manager.update_incident(
            incident_id=incident_id,
            status=incident_status,
            classification=classification,
            determination=determination,
            assign_to=assign_to
        )
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully updated incident {incident_id} in {INTEGRATION_DISPLAY_NAME}"

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UPDATE_INCIDENT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"Update Incident\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
