import utils

from AWSIAMManager import AWSIAMManager
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME, CREATE_GROUP
from exceptions import AWSIAMEntityAlreadyExistsException, AWSIAMValidationException, AWSIAMLimitExceededException

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {CREATE_GROUP}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    group_usernames = extract_action_param(siemplify,
                                           param_name="Group Name",
                                           is_mandatory=True,
                                           print_value=True,
                                           input_type=str)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    created_groups = []
    already_exists_group_usernames = []
    invalid_group_usernames = []
    after_reached_max = []
    json_results = []
    output_message = ''

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided credentials!')

        #  Get list of groups usernames from groups comma separated value
        group_usernames = utils.load_csv_to_list(group_usernames, "Group Name")

        for group_name in group_usernames:
            try:
                siemplify.LOGGER.info(f'Checking if the group name: {group_name} is a valid group name')
                if not utils.is_name_valid(group_name):
                    raise AWSIAMValidationException()
                siemplify.LOGGER.info(f'Group name: {group_name} is a valid group name')

                siemplify.LOGGER.info(f'Creating new group with name: {group_name}')
                group = manager.create_group(group_name=group_name)
                siemplify.LOGGER.info(f'Successfully created new group with name: {group_name}')

                created_groups.append(group_name)

                #  Creating JSON for group
                json_results.append(group.as_json())

            except AWSIAMEntityAlreadyExistsException as error:
                already_exists_group_usernames.append(group_name)
                siemplify.LOGGER.error(f'Could not add the following group to IAM {group_name} Names must be unique '
                                       f'within an account.')
                siemplify.LOGGER.exception(error)

            except AWSIAMValidationException as error:
                invalid_group_usernames.append(group_name)
                siemplify.LOGGER.info(f'Could not add the following group to IAM: {group_name}. Group usernames must '
                                      f'contain only alphanumeric characters and/or the following: +=.@_-.')
                siemplify.LOGGER.exception(error)

            except AWSIAMLimitExceededException as error:
                after_reached_max.append(group_name)
                siemplify.LOGGER.info(f'Could not add the following group to IAM: {group_name}. Reach to group limitation'
                                      f' in your aws account.')
                siemplify.LOGGER.exception(error)

        if already_exists_group_usernames:
            output_message += f"Could not add the following groups to IAM: {', '.join(already_exists_group_usernames)}. " \
                              f'Names must be unique within an account. \n'

        if invalid_group_usernames:
            output_message += f"Could not add the following groups to IAM: {', '.join(invalid_group_usernames)}. Group " \
                              f'names must contain only alphanumeric characters and/or the following: +=.@_-. \n'

        if after_reached_max:
            output_message += f"Could not add the following groups to IAM: {', '.join(after_reached_max)}. " \
                              f'Reach to Groups limitation in your aws account. \n'

        if created_groups:
            result_value = True
            siemplify.result.add_result_json(json_results)
            output_message = f"Successfully added the following groups to IAM: {', '.join(created_groups)}. \n" + output_message

        else:
            raise Exception(output_message)

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action {CREATE_GROUP}. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action {CREATE_GROUP}. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
