from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from AWSIAMManager import AWSIAMManager
from consts import INTEGRATION_NAME, INTEGRATION_NAME_SHORT, LIST_POLICIES_SCRIPT_NAME, DEFAULT_LIST_POLICIES_SCOPE, DEFAULT_MAX_RESULTS, \
    DEFAULT_MIN_RESULTS, DEFAULT_MAX_POLICIES_TO_RETURN
from exceptions import AWSIAMValidationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {LIST_POLICIES_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    only_attached = extract_action_param(siemplify, param_name="Only Attached", is_mandatory=False, print_value=True, default_value=False,
                                         input_type=bool)
    scope = extract_action_param(siemplify, param_name="Scope", is_mandatory=False, print_value=True,
                                 default_value=DEFAULT_LIST_POLICIES_SCOPE)

    max_policies_to_return = extract_action_param(siemplify,
                                                  param_name="Max Policies to Return",
                                                  is_mandatory=False,
                                                  default_value=DEFAULT_MAX_POLICIES_TO_RETURN,
                                                  print_value=True,
                                                  input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        if not DEFAULT_MIN_RESULTS <= max_policies_to_return <= DEFAULT_MAX_RESULTS:
            raise AWSIAMValidationException(f'Valid Range of "Max Policies to Return" is: [{DEFAULT_MIN_RESULTS}-'
                                            f'{DEFAULT_MAX_RESULTS}] \n')

        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_NAME_SHORT} Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info(f'Successfully connected to the {INTEGRATION_NAME_SHORT} server with the provided credentials!')

        siemplify.LOGGER.info('Listing AWS IAM account policies')
        has_more_results, policies = manager.list_policies(
            scope=scope,
            only_attached=only_attached,
            max_to_return=max_policies_to_return
        )
        siemplify.LOGGER.info('Successfully listed AWS IAM account policies')

        if not policies:
            output_message = f"No Policies were found in {INTEGRATION_NAME_SHORT}"
        else:
            siemplify.result.add_result_json([policy.as_json() for policy in policies])
            siemplify.LOGGER.info([policy.as_json() for policy in policies])
            siemplify.result.add_data_table('IAM Policies', construct_csv([policy.as_csv() for policy in policies]))
            output_message = f"Successfully listed available policies in {INTEGRATION_NAME_SHORT}."
            output_message += f" Please note, there are additional policies that match the provided filter." if has_more_results else ""

    except Exception as error:
        output_message = f"Error executing action {LIST_POLICIES_SCRIPT_NAME}. Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
