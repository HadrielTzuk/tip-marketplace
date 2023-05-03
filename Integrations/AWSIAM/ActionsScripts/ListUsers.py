from AWSIAMManager import AWSIAMManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from consts import INTEGRATION_NAME, LIST_USERS, DEFAULT_MAX_RESULTS, DEFAULT_MIN_RESULTS
from exceptions import AWSIAMValidationException

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {LIST_USERS}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    max_users_to_return = extract_action_param(siemplify,
                                               param_name="Max Users to Return",
                                               is_mandatory=False,
                                               print_value=True,
                                               input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = []
    users_as_csv = []
    result_value = True
    output_message = ''

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        if not DEFAULT_MIN_RESULTS <= max_users_to_return <= DEFAULT_MAX_RESULTS:
            raise AWSIAMValidationException(f'Valid Range of "Max Users to Return" is: [{DEFAULT_MIN_RESULTS}-'
                                            f'{DEFAULT_MAX_RESULTS}] \n')

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided credentials!')

        siemplify.LOGGER.info('Listing AWS IAM account users..')
        users = manager.list_users(max_users_to_return=max_users_to_return)
        siemplify.LOGGER.info('Successfully Listed AWS IAM account users')

        siemplify.LOGGER.info('Creating JSON and CSV result for users..')
        for user in users:
            json_results.append(user.as_json())
            users_as_csv.append(user.as_csv())

        if json_results:
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_data_table('IAM Users', construct_csv(users_as_csv))
            siemplify.LOGGER.info('Created JSON and CSV result for users')

        output_message += 'Successfully listed available users in AWS IAM.' if json_results else 'No users found in' \
                                                                                                 ' AWS IAM \n'

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action {LIST_USERS}. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action {LIST_USERS}. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()




