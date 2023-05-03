from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from XDRManager import XDRManager
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"PaloAltoCortexXDR"
SCRIPT_NAME = u"Get Device Violations"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    api_key_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key ID",
                                             is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    json_results = []
    status = EXECUTION_STATE_COMPLETED

    try:
        xdr_manager = XDRManager(api_root, api_key, api_key_id, verify_ssl)
        device_violations = xdr_manager.get_device_violations()

        if device_violations:
            device_violation_count = len(device_violations)
            json_results = [device_violation.raw_data for device_violation in device_violations]
            siemplify.result.add_data_table(u"Endpoints", construct_csv([device_violation.to_csv() for device_violation in device_violations]))
            output_message = u'Successfully listed device violations. Found {0} violations'.format(device_violation_count)
        else:
            output_message = u'No violations were found'
            device_violation_count = 0

    except Exception as e:
        siemplify.LOGGER.error(u"Failed listing violations. Error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        device_violation_count = 0
        output_message = u"Failed listing violations. Error: {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(device_violation_count))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, device_violation_count, status)


if __name__ == "__main__":
    main()
