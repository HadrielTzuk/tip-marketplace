from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from DarktraceManager import DarktraceManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME, \
    MODEL_BREACH_STATUSES
from DarktraceExceptions import NotFoundException, ErrorInResponseException, AlreadyAppliedException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Token",
                                            is_mandatory=True, print_value=True)
    api_private_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="API Private Token", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # Action parameters
    model_breach_status = extract_action_param(siemplify, param_name="Status", is_mandatory=True, print_value=True)
    model_breach_id = extract_action_param(siemplify, param_name="Model Breach ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = False
    status = EXECUTION_STATE_FAILED

    try:
        manager = DarktraceManager(api_root=api_root, api_token=api_token, api_private_token=api_private_token,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        model_breach = manager.get_model_breach(model_breach_id)

        if (model_breach_status == MODEL_BREACH_STATUSES.get("acknowledged") and model_breach.acknowledged) \
                or (model_breach_status == MODEL_BREACH_STATUSES.get("unacknowledged") and not model_breach.acknowledged):
            raise AlreadyAppliedException

        if model_breach_status == MODEL_BREACH_STATUSES.get("acknowledged"):
            manager.acknowledge_model_breach(model_breach_id)

        if model_breach_status == MODEL_BREACH_STATUSES.get("unacknowledged"):
            manager.unacknowledge_model_breach(model_breach_id)

        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully updated status of the model breach \"{model_breach_id}\" to " \
                         f"\"{model_breach_status}\" in {INTEGRATION_DISPLAY_NAME}."

    except AlreadyAppliedException:
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Model breach \"{model_breach_id}\" already has status \"{model_breach_status}\" " \
                         f"in {INTEGRATION_DISPLAY_NAME}. "
    except ErrorInResponseException:
        output_message = f"Error executing action \"{UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME}\". Reason: model breach" \
                         f" \"{model_breach_id}\" wasn't found in {INTEGRATION_DISPLAY_NAME}.'"
    except NotFoundException:
        output_message = f"Error executing action \"{UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME}\". Reason: model breach" \
                         f" \"{model_breach_id}\" wasn't found in {INTEGRATION_DISPLAY_NAME}.'"
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action {UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME}. Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
