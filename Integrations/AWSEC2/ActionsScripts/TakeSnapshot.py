from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    ACTION_NAME = "Take Snapshot"
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, ACTION_NAME)
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

    instance_id = extract_action_param(siemplify,
                                       param_name="Instance ID",
                                       is_mandatory=True,
                                       print_value=True)

    description = extract_action_param(siemplify,
                                       param_name="Description",
                                       is_mandatory=False,
                                       print_value=True)

    description = '' if not description else description

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_DISPLAY_NAME} Service')
        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info(f"Successfully connected to {INTEGRATION_DISPLAY_NAME} service")

        siemplify.LOGGER.info("Creating snapshot for AWS EC2 instance")
        snapshot_obj = manager.create_snapshots(instance_id=instance_id, description=description)
        siemplify.LOGGER.info("Successfully created snapshot for AWS EC2 instance")

        if snapshot_obj:
            siemplify.result.add_result_json({'EC2_Snapshot': snapshot_obj.as_json()})

            result_value = True
            output_message = "Successfully created snapshot."

        else:
            result_value = False
            output_message = "No snapshot created in AWS EC2"

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{ACTION_NAME}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action '{ACTION_NAME}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
