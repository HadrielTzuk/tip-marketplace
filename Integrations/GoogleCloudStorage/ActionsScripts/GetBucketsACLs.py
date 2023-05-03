import json

from TIPCommon import extract_configuration_param, extract_action_param

import consts
import utils
from GoogleCloudStorageManager import GoogleCloudStorageManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import GoogleCloudStorageBadRequestError, GoogleCloudStorageNotFoundError, GoogleCloudStorageForbiddenError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {consts.GET_BUCKETS_ACLS}"
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

    bucket_names = extract_action_param(siemplify, param_name="Bucket Name",
                                        is_mandatory=True,
                                        print_value=True,
                                        input_type=str)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = []
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    found_buckets = []
    not_found_buckets = []
    uniform_buckets = []
    output_message = ''

    try:
        creds = json.loads(creds)
        manager = GoogleCloudStorageManager(**creds, verify_ssl=verify_ssl)

        bucket_names = utils.load_csv_to_list(bucket_names, "Bucket Name")

        for bucket_name in bucket_names:
            try:
                siemplify.LOGGER.info(f'Fetching ACLs of bucket with name: {bucket_name}')
                acl = manager.get_acl(bucket_name)
                siemplify.LOGGER.info(f'Successfully fetched ACLs of bucket with name: {bucket_name}')

                json_results.append({
                    'BucketName': bucket_name,
                    'BucketACLs': acl.as_json()
                })

                found_buckets.append(bucket_name)

            except GoogleCloudStorageBadRequestError as error:
                uniform_buckets.append(bucket_name)
                siemplify.LOGGER.error(f'Failed to fetch bucket with name: {error}')
                siemplify.LOGGER.exception(error)

            except (GoogleCloudStorageNotFoundError, GoogleCloudStorageForbiddenError) as error:
                not_found_buckets.append(bucket_name)
                siemplify.LOGGER.error(f'Failed to find bucket with name: {error}')
                siemplify.LOGGER.exception(error)

            except Exception as error:
                raise Exception(error)

        if json_results:
            siemplify.result.add_result_json(json_results)
            output_message = f'Successfully retrieved the access control list (ACL) for the ' \
                             f"Cloud Storage buckets: {', '.join(found_buckets)}\n"

        if uniform_buckets:
            output_message += "Action wasn’t able to return the access control list(ACL) for the Cloud Storage " \
                              f"buckets {', '.join(uniform_buckets)} Reason: Cannot get legacy ACL for a bucket that " \
                              f"has uniform bucket-level access. Read more at " \
                              f"https://cloud.google.com/storage/docs/uniform-bucket-level-access\n"

        if not_found_buckets:
            output_message += 'Action wasn’t able to return the access control list(ACL) for the ' \
                              f"Cloud Storage buckets: {', '.join(not_found_buckets)}\n"

        result_value = True if json_results else False

    except json.decoder.JSONDecodeError as error:
        status = EXECUTION_STATE_FAILED
        output_message = "Unable to parse credentials as JSON. Please validate creds."
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(error)

    except Exception as error:
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action '{consts.GET_BUCKETS_ACLS}'. Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
