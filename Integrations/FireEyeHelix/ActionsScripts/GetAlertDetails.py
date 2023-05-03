from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FireEyeHelixConstants import PROVIDER_NAME, GET_ALERT_DETAILS_SCRIPT_NAME, NOTES_LIMIT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from FireEyeHelixExceptions import FireEyeHelixNotFoundAlertException

TABLE_HEADER = "Notes"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ALERT_DETAILS_SCRIPT_NAME
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Root",
        is_mandatory=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Token",
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool
    )

    # Parameters
    alert_id = extract_action_param(siemplify, param_name='Alert ID', is_mandatory=True, print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Notes To Return', default_value=NOTES_LIMIT,
                                 is_mandatory=False, input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        alert = manager.get_alert_details(alert_id=alert_id)

        if alert:
            output_message = "Successfully returned information about the alert with ID {} from {}.".format(
                alert_id, PROVIDER_NAME)
            siemplify.result.add_result_json(alert.to_json())
            result_value = True
            if alert.notes:
                siemplify.result.add_data_table(title=TABLE_HEADER,
                                                data_table=construct_csv([note.to_csv() for note in alert.notes[:limit]]))
        else:
            output_message = "Action wasn’t able to return information about the alert with ID {0} from {1}. Reason: " \
                             "Alert with ID {0} wasn't found".format(alert_id, PROVIDER_NAME)

    except FireEyeHelixNotFoundAlertException:
        output_message = "Action wasn’t able to return information about the alert with ID {0} from {1}. Reason: " \
                         "Alert with ID {0} wasn't found".format(alert_id, PROVIDER_NAME)

    except Exception as e:
        output_message = "Error executing action \"Get Alert Details\". Reason: {}".format(e)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
