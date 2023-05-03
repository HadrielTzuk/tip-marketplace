from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from Microsoft365DefenderManager import Microsoft365DefenderManager, NotFoundItemException
from constants import INTEGRATION_NAME, ADD_COMMENT_TO_INCIDENT_SCRIPT_NAME, INTEGRATION_DISPLAY_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_INCIDENT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="API Root",
        is_mandatory=True,
        print_value=True
    )
    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Tenant ID",
        is_mandatory=True,
        print_value=True
    )
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client ID",
        is_mandatory=True,
        print_value=True
    )
    client_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client Secret",
        is_mandatory=True,
        remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    # Action parameters
    incident_id = extract_action_param(
        siemplify,
        param_name="Incident ID",
        is_mandatory=True,
        print_value=True
    )
    comment = extract_action_param(
        siemplify,
        param_name="Comment",
        is_mandatory=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        try:
            incident_id = int(incident_id)
        except ValueError:
            raise NotFoundItemException(f"incident \"{incident_id}\" wasn't found in Microsoft 365 Defender")

        manager = Microsoft365DefenderManager(api_root=api_root, tenant_id=tenant_id, client_id=client_id,
                                              client_secret=client_secret, verify_ssl=verify_ssl,
                                              siemplify=siemplify)
        manager.update_incident(
            incident_id=incident_id,
            comment=comment
        )
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully added comment to incident {incident_id} in {INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ADD_COMMENT_TO_INCIDENT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"Add Comment To Incident\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
