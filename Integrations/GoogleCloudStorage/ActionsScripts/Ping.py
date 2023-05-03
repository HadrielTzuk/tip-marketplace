import json

from TIPCommon import extract_configuration_param

import consts
from GoogleCloudStorageManager import GoogleCloudStorageManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {consts.PING}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="Service Account",
                                        is_mandatory=True)
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=consts.INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        creds = json.loads(creds)
        manager = GoogleCloudStorageManager(**creds, verify_ssl=verify_ssl)
        manager.test_connectivity()
        output_message = f'Successfully connected to the {consts.INTEGRATION_DISPLAY_NAME} server with the provided connection parameters!'
        result_value = True

    except json.decoder.JSONDecodeError as error:
        output_message = "Unable to parse credentials as JSON. Please validate creds."
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    except Exception as error:
        siemplify.LOGGER.error(f"Failed to connect to the {consts.INTEGRATION_DISPLAY_NAME} server! Error is: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to the {consts.INTEGRATION_DISPLAY_NAME} server! Error is: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
