from SiemplifyAction import SiemplifyAction
from RecordedFutureManager import RecordedFutureManager
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import PROVIDER_NAME, GET_ALERT_DETAILS_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import RecordedFutureNotFoundError, RecordedFutureUnauthorizedError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ALERT_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_url = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiUrl")
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiKey")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    alert_id = extract_action_param(siemplify, param_name="Alert ID", is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    is_success = False
    status = EXECUTION_STATE_FAILED

    try:
        recorded_future_manager = RecordedFutureManager(api_url, api_key, verify_ssl=verify_ssl)
        alert_object = recorded_future_manager.get_information_about_alert(alert_id)
        siemplify.result.add_result_json(alert_object.to_json())
        siemplify.result.add_link("Web Report Link:", alert_object.alert_url)

        is_success = True
        status = EXECUTION_STATE_COMPLETED
        output_message = 'Successfully fetched the following Alert ID details from Recorded Future: \n{}'\
            .format(alert_id)

    except RecordedFutureUnauthorizedError as e:
        output_message = "Unauthorized - please check your API token and try again. {}".format(e)
    except RecordedFutureNotFoundError as e:
        output_message = "Requested Alert ID wasn't found in Recorded Future, or something went wrong in executing " \
                         "action {}. Reason: {}".format(GET_ALERT_DETAILS_SCRIPT_NAME, e)
    except Exception as e:
        output_message = "Error executing action {}. Reason: {}".format(GET_ALERT_DETAILS_SCRIPT_NAME, e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))
    siemplify.LOGGER.info('Result: {}'.format(is_success))
    siemplify.LOGGER.info('Status: {}'.format(status))

    siemplify.end(output_message, is_success, status)


if __name__ == '__main__':
    main()
