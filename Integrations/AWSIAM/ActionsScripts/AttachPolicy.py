from TIPCommon import extract_configuration_param, extract_action_param

import utils
from AWSIAMManager import AWSIAMManager
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, ATTACH_POLICY_SCRIPT_NAME, GROUP_IDENTITY_TYPE, USER_IDENTITY_TYPE, ROLE_IDENTITY_TYPE
from exceptions import AWSIAMEntityNotFoundException, AWSIAMValidationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {ATTACH_POLICY_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    identity_type = extract_action_param(siemplify, param_name="Identity Type", is_mandatory=True, print_value=True,
                                         default_value=GROUP_IDENTITY_TYPE)
    identity_name = extract_action_param(siemplify, param_name="Identity Name", is_mandatory=True, print_value=True)
    policy_name = extract_action_param(siemplify, param_name="Policy Name", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_FAILED
    result_value = False

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        if not (utils.is_name_valid(identity_name) and utils.is_name_valid(policy_name)):
            raise AWSIAMValidationException(f"Could not attach {policy_name} to {identity_type}:{identity_name}. Names must contain only "
                                            f"alphanumeric characters and/or the following: +=,.@_-")

        policy_arn = manager.get_policy_arn(policy_name)

        try:
            if identity_type == GROUP_IDENTITY_TYPE:
                manager.attach_group_policy(
                    group_name=identity_name,
                    policy_arn=policy_arn
                )
            elif identity_type == USER_IDENTITY_TYPE:
                manager.attach_user_policy(
                    user_name=identity_name,
                    policy_arn=policy_arn
                )
            elif identity_type == ROLE_IDENTITY_TYPE:
                manager.attach_role_policy(
                    role_name=identity_name,
                    policy_arn=policy_arn
                )
            else:
                raise Exception("Failed to validate IAM identity type.")

            output_message = f"Policy was attached to {identity_type}:{identity_name}."
            result_value = True
            status = EXECUTION_STATE_COMPLETED

        except AWSIAMEntityNotFoundException as error:
            output_message = f"Could not attach {policy_name} to {identity_type}: {identity_name}. {identity_type} {identity_name} could " \
                             f"not be found."
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)

    except AWSIAMValidationException as error:
        output_message = f"{error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except AWSIAMEntityNotFoundException as error:
        output_message = f"Could not attach {policy_name} to {identity_type}: {identity_name}. Policy could not be found."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except Exception as error:
        output_message = f"Error executing action {ATTACH_POLICY_SCRIPT_NAME}. Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
