import utils

from AWSIAMManager import AWSIAMManager
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME, CREATE_USER
from exceptions import AWSIAMEntityAlreadyExistsException, AWSIAMValidationException, AWSIAMLimitExceededException

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {CREATE_USER}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    usernames = extract_action_param(siemplify,
                                     param_name="User Name",
                                     is_mandatory=True,
                                     print_value=True,
                                     input_type=str)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    created_usernames = []
    already_exists_usernames = []
    invalid_usernames = []
    after_reached_max = []
    json_results = []
    output_message = ''

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided credentials!')

        #  Get list of hunt ids from hunts comma separated value
        usernames = utils.load_csv_to_list(usernames, "Username")

        for username in usernames:
            try:
                siemplify.LOGGER.info(f'Checking if the username: {username} is a valid username')
                if not utils.is_name_valid(username):
                    raise AWSIAMValidationException()
                siemplify.LOGGER.info(f'username: {username} is a valid username')

                siemplify.LOGGER.info(f'Creating new user with username: {username}')
                user = manager.create_user(username=username)
                siemplify.LOGGER.info(f'Successfully created new user with username: {username}')

                created_usernames.append(username)

                #  Creating JSON for user
                json_results.append(user.as_json())

            except AWSIAMEntityAlreadyExistsException as error:
                already_exists_usernames.append(username)
                siemplify.LOGGER.error(f'Could not add the following users to IAM {username} Names must be unique '
                                       f'within an account.')
                siemplify.LOGGER.exception(error)

            except AWSIAMValidationException as error:
                invalid_usernames.append(username)
                siemplify.LOGGER.info(f'Could not add the following user to IAM: {username}. Usernames must '
                                      f'contain only alphanumeric characters and/or the following: +=.@_-.')
                siemplify.LOGGER.exception(error)

            except AWSIAMLimitExceededException as error:
                after_reached_max.append(username)
                siemplify.LOGGER.info(f'Could not add the following user to IAM: {username}. Reach to Users limitation'
                                      f' in your aws account.')
                siemplify.LOGGER.exception(error)

        if already_exists_usernames:
            output_message += f"Could not add the following users to IAM: {', '.join(already_exists_usernames)}. " \
                              f'Names must be unique within an account. \n'

        if invalid_usernames:
            output_message += f"Could not add the following users to IAM: {', '.join(invalid_usernames)}. " \
                              f'Usernames must contain only alphanumeric characters and/or the following: +=.@_-. \n'

        if after_reached_max:
            output_message += f"Could not add the following users to IAM: {', '.join(after_reached_max)}. " \
                              f'Reach to Users limitation in your aws account. \n'

        if created_usernames:
            result_value = True
            siemplify.result.add_result_json(json_results)
            output_message = f"Successfully added the following users to IAM: {', '.join(created_usernames)}. \n" + output_message

        else:
            raise Exception(output_message)

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action 'Create a User'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action 'Create a User'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
