import json

import utils
from AWSIAMManager import AWSIAMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME, CREATE_POLICY_SCRIPT_NAME
from exceptions import AWSIAMEntityAlreadyExistsException, AWSIAMValidationException, AWSIAMMalformedPolicyDocument


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {CREATE_POLICY_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    policy_name = extract_action_param(siemplify, param_name="Policy Name", is_mandatory=True, print_value=True)
    policy_document = extract_action_param(siemplify, param_name="Policy Document", is_mandatory=True, print_value=True)
    policy_description = extract_action_param(siemplify, param_name="Description", is_mandatory=False, print_value=True, default_value=None)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_FAILED
    result_value = False

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided credentials!')

        try:
            siemplify.LOGGER.info("Validating policy document")
            try:
                policy_document = json.loads(policy_document)
                policy_document_str = json.dumps(policy_document)
            except Exception:
                raise AWSIAMMalformedPolicyDocument(f"Failed to load JSON policy document")
            siemplify.LOGGER.info("Successfully validated policy document")

            siemplify.LOGGER.info(f'Validating policy name {policy_name}')
            if not utils.is_name_valid(policy_name):
                raise AWSIAMValidationException(f"Failed to validate policy name {policy_name}")
            siemplify.LOGGER.info(f"Successfully validate policy name {policy_name}")

            siemplify.LOGGER.info(f'Creating new policy with name: {policy_name}')

            policy = manager.create_policy(
                policy_name=policy_name,
                policy_document=policy_document_str,
                description=policy_description
            )
            siemplify.LOGGER.info(f'Successfully created new policy with name: {policy_name}')

            siemplify.result.add_result_json(policy.as_json())
            output_message = f"{policy_name} policy was successfully created."
            result_value = True
            status = EXECUTION_STATE_COMPLETED

        except AWSIAMEntityAlreadyExistsException as error:
            output_message = f'Could not create {policy_name} policy. Policy names must be unique within an account.'
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)

        except AWSIAMValidationException as error:
            output_message = f'Could not create {policy_name} policy. Policy names must contain only alphanumeric characters and/or the ' \
                             f'following: +=,.@_-.'
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)

        except AWSIAMMalformedPolicyDocument as error:
            output_message = f"Could not create {policy_name} policy. The policy document was malformed. Reason: {error}"
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)

    except Exception as error:
        siemplify.LOGGER.error(f"Error executing action {CREATE_POLICY_SCRIPT_NAME}. Reason: {error}")
        siemplify.LOGGER.exception(error)
        output_message = f"Error executing action {CREATE_POLICY_SCRIPT_NAME}. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
