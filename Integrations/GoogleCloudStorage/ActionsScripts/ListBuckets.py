import json

from TIPCommon import extract_configuration_param, extract_action_param

import consts
from GoogleCloudStorageManager import GoogleCloudStorageManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from exceptions import GoogleCloudStorageBadRequestError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {consts.LIST_BUCKETS}"
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

    max_results = extract_action_param(siemplify, param_name="Max Results",
                                       is_mandatory=False,
                                       print_value=True,
                                       default_value=50,
                                       input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = {'Buckets': []}
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        creds = json.loads(creds)
        manager = GoogleCloudStorageManager(**creds, verify_ssl=verify_ssl)

        if max_results < consts.MIN_LIST_SIZE:
            siemplify.LOGGER.info(f"'Max Results' value must be equals or greater than: {consts.MIN_LIST_SIZE}. "
                                  f"The default value: {consts.DEFAULT_PAGE_SIZE} will be assigned instead")
            max_results = consts.DEFAULT_PAGE_SIZE

        siemplify.LOGGER.info(f"Fetching buckets from {consts.INTEGRATION_DISPLAY_NAME}")
        buckets = manager.list_buckets(max_results=max_results)
        siemplify.LOGGER.info(f"Successfully fetched buckets from {consts.INTEGRATION_DISPLAY_NAME}")

        for bucket in buckets:
            json_results['Buckets'].append(bucket.as_json())

        if json_results['Buckets']:
            convert_dict_to_json_result_dict(json_results)
            siemplify.result.add_result_json(json_results)

        result_value = True
        output_message = 'Successfully listed available buckets in Google Cloud Storage.'

    except GoogleCloudStorageBadRequestError:
        output_message = 'Action wasn’t able to list available buckets in Google Cloud Storage.'
        siemplify.LOGGER.info(output_message)

    except json.decoder.JSONDecodeError as error:
        output_message = "Unable to parse credentials as JSON. Please validate creds."
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    except Exception as error:
        status = EXECUTION_STATE_FAILED
        output_message = f'Error executing action {consts.LIST_BUCKETS}. Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
