from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, INSTANCES_TABLE_NAME, LIST_INSTANCES, EC2_JSON_INSTANCES, TAG_PREFIX, MAX_RESULTS_LIMIT, DEFAULT_MAX_RESULTS
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, LIST_INSTANCES)
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

    instance_ids = extract_action_param(siemplify,
                                        param_name="Instance IDs",
                                        is_mandatory=False,
                                        print_value=True)

    tag_filters = extract_action_param(siemplify,
                                       param_name="Tag Filters",
                                       is_mandatory=False,
                                       print_value=True)

    result_value = False
    output_message = ""

    try:
        max_results = extract_action_param(siemplify,
                                           param_name="Max Results",
                                           input_type=int,
                                           is_mandatory=False,
                                           print_value=True)

        if max_results and max_results > MAX_RESULTS_LIMIT:
            siemplify.LOGGER.info(f"'Max Results' should be in range of [0, 1000]. {DEFAULT_MAX_RESULTS} will be set")
            max_results = DEFAULT_MAX_RESULTS

        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_DISPLAY_NAME} Service')
        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                      aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info(f"Successfully connected to {INTEGRATION_DISPLAY_NAME} service")

        # Split the instances ids if exists
        instance_ids_list = load_csv_to_list(instance_ids, "Instances IDs", ',') if instance_ids else []

        # Split the tag filters if exists
        filters = []
        tag_filters_list = load_csv_to_list(tag_filters, "Tag Filters", ',') if tag_filters else []
        # [key:value]

        for tag_filter in tag_filters_list:
            separated_filter = tag_filter.split(':')

            filters.append({
                'Name': TAG_PREFIX + separated_filter[0],
                'Values': [separated_filter[1]]
            })

        if instance_ids_list and max_results:
            siemplify.LOGGER.info("Instance IDs cannot be used with the parameter Max Results. "
                                  "Instance IDs has priority over the Max Result parameter.")
            max_results = None

        siemplify.LOGGER.info("Fetching instances from AWS EC2 service")
        instances_objs = manager.list_instances(instance_ids=instance_ids_list,
                                                tag_filters=filters,
                                                max_results=max_results)
        siemplify.LOGGER.info("Successfully fetched instances from AWS EC2 service")

        siemplify.LOGGER.info("Starting processing instances")
        instances_jsons = []
        instances_csvs = []

        if instances_objs:
            for instance in instances_objs:
                instances_jsons.extend(instance.as_json())
                instances_csvs.extend(instance.as_csvs())

            siemplify.result.add_result_json({'EC2_Instances': instances_jsons})
            siemplify.result.add_data_table(INSTANCES_TABLE_NAME, construct_csv(instances_csvs))

            result_value = True
            output_message = "Successfully described AWS EC2 instances."

        else:
            result_value = False
            output_message = "No instances were found in AWS EC2"

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{LIST_INSTANCES}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{LIST_INSTANCES}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
