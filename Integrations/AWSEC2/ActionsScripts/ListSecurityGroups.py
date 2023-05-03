from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, LIST_SECURITY_GROUPS, SECURITY_GROUP_TABLE_NAME, TAG_PREFIX, MAX_RESULTS_LIMIT, \
    DEFAULT_MAX_RESULTS, EC2_JSON_SECURITY_GROUPS
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, LIST_SECURITY_GROUPS)
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

    security_group_names = extract_action_param(siemplify,
                                                param_name="Security Group Names",
                                                is_mandatory=False,
                                                print_value=True)

    security_group_ids = extract_action_param(siemplify,
                                              param_name="Security Group IDs",
                                              is_mandatory=False,
                                              print_value=True)

    tag_filters = extract_action_param(siemplify,
                                       param_name="Tag Filters",
                                       is_mandatory=False,
                                       print_value=True)

    result_value = False
    output_message = "No security groups were found in AWS EC2"

    try:
        max_results = extract_action_param(siemplify,
                                           param_name="Max Results",
                                           input_type=int,
                                           is_mandatory=False,
                                           print_value=True)

        if max_results and max_results > MAX_RESULTS_LIMIT:
            siemplify.LOGGER.info(f"'Max Results' should be in range of [0, 1000]. {DEFAULT_MAX_RESULTS} will be set")
            max_results = DEFAULT_MAX_RESULTS

        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)

        # Split the security groups names if exists
        security_group_names_list = load_csv_to_list(security_group_names, "Security Group Names", ',') if \
            security_group_names else []

        # Split the security groups ids if exists
        security_group_ids_list = load_csv_to_list(security_group_ids, "Security Group IDs", ',') if \
            security_group_ids else []

        # Split the tag filters if exists
        filters = []
        tag_filters_list = load_csv_to_list(tag_filters, "Tag Filters", ',') if tag_filters else []
        # [key:value]

        for tag_filter in tag_filters_list:
            separated_filter = tag_filter.split(':')

            if len(separated_filter) > 1:
                # {'Name': 'tag:filter_name', ['value']}
                filters.append({
                    'Name': TAG_PREFIX + separated_filter[0],
                    'Values': [separated_filter[1]]
                })
            else:
                siemplify.LOGGER.info(f"{tag_filter} is not in a valid form. Tags must be in the form: tag_name:value")

        if (security_group_names_list or security_group_ids_list) and max_results:
            siemplify.LOGGER.info("Security Group Names and Security Group IDs cannot be used with the parameter Max"
                                  " Results. Security Group Names and Security Group IDs has priority over the Max Result parameter.")
            max_results = None

        siemplify.LOGGER.info("Fetching security groups from AWS EC2 service")
        security_group_objs = manager.list_security_groups(security_group_names=security_group_names_list,
                                                           group_ids=security_group_ids_list,
                                                           tag_filters=filters,
                                                           max_results=max_results)
        siemplify.LOGGER.info("Successfully fetched security groups from AWS EC2 service")

        siemplify.LOGGER.info("Starting processing security groups")
        security_group_jsons = []
        security_group_csvs = []

        if security_group_objs:
            for security_group in security_group_objs:
                if ((security_group_ids_list and security_group.group_id not in security_group_ids_list) or
                        (security_group_names_list and security_group.group_name not in security_group_names_list)):
                    continue
                security_group_jsons.append(security_group.as_json())
                security_group_csvs.append(security_group.as_csv())

            siemplify.result.add_result_json({EC2_JSON_SECURITY_GROUPS: security_group_jsons})
            siemplify.result.add_data_table(SECURITY_GROUP_TABLE_NAME, construct_csv(security_group_csvs))

            result_value = True
            output_message = "Successfully described AWS EC2 security groups."

        else:
            result_value = False
            output_message = "No security groups were found in AWS EC2"

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{LIST_SECURITY_GROUPS}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{LIST_SECURITY_GROUPS}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
