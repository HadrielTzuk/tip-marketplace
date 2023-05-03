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
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {consts.LIST_BUCKET_OBJECTS}"
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

    bucket_name = extract_action_param(siemplify, param_name="Bucket Name",
                                       is_mandatory=True,
                                       print_value=True,
                                       input_type=str)

    max_objects_to_return = extract_action_param(siemplify, param_name="Max Objects to Return",
                                                 is_mandatory=False,
                                                 print_value=True,
                                                 default_value=50,
                                                 input_type=int)

    retrieve_acl = extract_action_param(siemplify, param_name="Retrieves the Access Control List of an object",
                                        is_mandatory=False,
                                        print_value=True,
                                        default_value=False,
                                        input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = {'Objects': []}
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        try:
            creds = json.loads(creds)
        except Exception:
            raise Exception("Unable to parse credentials as JSON. Please validate creds.")
        manager = GoogleCloudStorageManager(**creds, verify_ssl=verify_ssl)

        if max_objects_to_return < consts.MIN_LIST_SIZE:
            siemplify.LOGGER.info(f"'Max Objects to Return' value must be equals or greater than: {consts.MIN_LIST_SIZE}. "
                                  f"The default value: {consts.DEFAULT_PAGE_SIZE} will be assigned instead")
            max_objects_to_return = consts.DEFAULT_PAGE_SIZE

        siemplify.LOGGER.info(f"Fetching buckets objects from {consts.INTEGRATION_DISPLAY_NAME}")
        objects = manager.list_buckets_objects(bucket_name=bucket_name, max_objects_to_return=max_objects_to_return,
                                               retrieve_acl=retrieve_acl)
        siemplify.LOGGER.info(f"Successfully fetched buckets objects from {consts.INTEGRATION_DISPLAY_NAME}")

        for obj in objects:
            json_results['Objects'].append(obj.as_json())

        if json_results['Objects']:
            convert_dict_to_json_result_dict(json_results)
            siemplify.result.add_result_json(json_results)

        result_value = True
        output_message = f"Successfully returned objects of the '{bucket_name}' bucket in {consts.INTEGRATION_DISPLAY_NAME}."

    except GoogleCloudStorageBadRequestError as error:
        output_message = f"Action wasn’t able to return objects of the ‘{bucket_name}’ bucket in {consts.INTEGRATION_DISPLAY_NAME}. " \
                         f"Reason: {error}"
        siemplify.LOGGER.info(f"Action wasn’t able to return objects of the ‘{bucket_name}’ bucket in {consts.INTEGRATION_DISPLAY_NAME}. "
                              f"Reason: {error}")

    except Exception as error:
        status = EXECUTION_STATE_FAILED
        output_message = f'Error executing action {consts.LIST_BUCKET_OBJECTS}. Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
