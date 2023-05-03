from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    GET_EVENT_OFFSET_SCRIPT_NAME,
    API_ROOT_DEFAULT,
    SIEMPLIFY_PREFIX_FOR_APP,
    PRODUCT_NAME
)
import uuid
from utils import timestamp_to_iso


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_EVENT_OFFSET_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    limit = extract_action_param(siemplify, param_name='Max Events To Process', input_type=int, print_value=True,
                                 is_mandatory=True)
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = f'No events were found in {PRODUCT_NAME}.'
    app_name = f"{SIEMPLIFY_PREFIX_FOR_APP}{str(uuid.uuid4()).replace('-', '')}"[:30]

    try:
        if limit < 1:
            raise Exception("\"Max Events To Process\" must be greater than 0.")

        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root)

        detections = manager.get_stream_detections(app_name=app_name, offset=None, limit=limit)

        if detections:
            last_detection = sorted(detections, key=lambda det: det.offset)[-1]
            output_message = f'Successfully retrieved event offset in {PRODUCT_NAME}.'
            siemplify.result.add_result_json({"offset": last_detection.offset,
                                              "timestamp":timestamp_to_iso(last_detection.event_creation_time) })
            result_value = True

    except Exception as e:
        output_message = f"Error executing action '{GET_EVENT_OFFSET_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
