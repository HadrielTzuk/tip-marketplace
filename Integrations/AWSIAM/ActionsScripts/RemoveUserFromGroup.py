from TIPCommon import extract_configuration_param, extract_action_param

from AWSIAMManager import AWSIAMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, REMOVE_USER_FROM_GROUP_SCRIPT_NAME
from exceptions import AWSIAMLimitExceededException, AWSIAMEntityNotFoundException
from utils import load_csv_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, REMOVE_USER_FROM_GROUP_SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    group_name = extract_action_param(siemplify, param_name='Group Name', is_mandatory=True, print_value=True)
    user_names = extract_action_param(siemplify, param_name='User Name', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    not_found_entities = ""
    output_message = ""
    failed_users = []
    exceeding_limit_usernames = []
    successful_users = []
    result_value = False

    try:
        user_names = load_csv_to_list(user_names, param_name='User Name')
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided credentials!')

        for user_name in user_names:
            try:
                siemplify.LOGGER.info(f"Removing user {user_name} from group {group_name}")
                manager.remove_user_from_group(
                    group_name=group_name,
                    user_name=user_name
                )
                successful_users.append(user_name)

            except AWSIAMEntityNotFoundException as error:
                siemplify.LOGGER.error(f"Specified group {group_name} or user {user_name} doesn't exist.")
                siemplify.LOGGER.exception(error)
                # This exception catches both non existing User/Group. Saving error message as output message
                not_found_entities += f" {error}\n"

            except AWSIAMLimitExceededException as error:
                siemplify.LOGGER.error(
                    f"Could not remove {user_name} from {group_name} because it attempted to create resources beyond the "
                    f"current AWS account limits.")
                siemplify.LOGGER.exception(error)
                exceeding_limit_usernames.append(user_name)

            except Exception as error:
                siemplify.LOGGER.error(f"Could not remove {user_name} from {group_name}")
                siemplify.LOGGER.exception(error)
                failed_users.append(user_name)

        if successful_users:
            siemplify.LOGGER.info(f"{', '.join(successful_users)} has been removed from group: {group_name}")
            output_message += f"{', '.join(successful_users)} has been removed from group: {group_name}\n"
            result_value = True

        if exceeding_limit_usernames:
            output_message += f"Could not remove {', '.join(exceeding_limit_usernames)} from {group_name} because it attempted to create resources beyond the " \
                              f"current AWS account limits.\n"

        if not_found_entities:
            output_message += not_found_entities

        if failed_users:
            output_message += f"Could not remove {', '.join(failed_users)} from {group_name}.\n"

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action '{REMOVE_USER_FROM_GROUP_SCRIPT_NAME}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action '{REMOVE_USER_FROM_GROUP_SCRIPT_NAME}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
