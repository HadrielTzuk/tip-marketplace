from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, CREATE_TAGS, EC2_JSON_INSTANCES
from utils import load_csv_to_list, handle_tags
from exceptions import AWSEC2ValidationException, AWSEC2LimitExceededException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, CREATE_TAGS)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify,
                                                     provider_name=INTEGRATION_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    resource_ids = extract_action_param(siemplify,
                                        param_name="Resource IDs",
                                        is_mandatory=True,
                                        print_value=True)

    tags = extract_action_param(siemplify,
                                param_name="Tags",
                                is_mandatory=True,
                                print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)

        manager.test_connectivity()

        # Split the instances ids
        resource_ids_list = load_csv_to_list(resource_ids, "Resources IDs", ',')

        # Split the tags
        formatted_tags = []
        tags_list = load_csv_to_list(tags, "Tags", ',')

        siemplify.LOGGER.info("Validates and preparing the tags to add to the resources")
        valid_tags, invalid_tags, not_unique_tags = handle_tags(tags_list)
        siemplify.LOGGER.info("successfully validated and prepared the tags to add to the resources")

        invalid_resource_ids = []
        limit_exceeded_ids = []
        success_ids = []

        if valid_tags:
            siemplify.LOGGER.info("Creating tags for AWS resources")
            for resource_id in resource_ids_list:
                try:
                    manager.create_tags(resources_id=[resource_id], tags=valid_tags)
                    success_ids.append(resource_id)
                    siemplify.LOGGER.info(f"Successfully added the input tags to resource with id: {resource_id}")

                except AWSEC2ValidationException as error:
                    siemplify.LOGGER.exception(error)
                    invalid_resource_ids.append(resource_id)

                except AWSEC2LimitExceededException as error:
                    siemplify.LOGGER.exception(error)
                    limit_exceeded_ids.append(resource_id)
            siemplify.LOGGER.info("tags were created for AWS resources")

        output_message = ''
        result_value = False
        tags_list_str = ", ".join([tag.get('Key') + ':' + tag.get('Value') for tag in valid_tags])
        resource_ids_list_str = ", ".join(resource_ids_list)

        if success_ids:
            result_value = True
            success_ids_str = ", ".join(success_ids)
            output_message += f"Successfully added {tags_list_str} tags to the following resources: {success_ids_str}\n"

        if invalid_resource_ids:
            invalid_resource_ids_str = ", ".join(invalid_resource_ids)
            output_message += f"Failed to add {tags_list_str} tags to the following resources: " \
                              f"{invalid_resource_ids_str}. Reason: Invalid resource ID\n"

        if limit_exceeded_ids:
            limit_exceeded_ids_str = ", ".join(limit_exceeded_ids)
            output_message += f"Failed to add {tags_list_str} tags to the following resources: " \
                              f"{limit_exceeded_ids_str}. Reason: resource can have a maximum of 50 tags.\n"

        if invalid_tags:
            invalid_tags_tags_str = ", ".join(invalid_tags)
            output_message += f"Failed to add {invalid_tags_tags_str} tags to the following resources: " \
                              f"{resource_ids_list_str}. Reason: Invalid format. Tag should include key and value.\n"

        if not_unique_tags:
            not_unique_tags_str = ", ".join(not_unique_tags)
            output_message += f"Failed to add {not_unique_tags_str} tags to the following resources: " \
                              f"{resource_ids_list_str}. Reason: Tag keys must be unique per resource.\n"

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{CREATE_TAGS}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{CREATE_TAGS}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
