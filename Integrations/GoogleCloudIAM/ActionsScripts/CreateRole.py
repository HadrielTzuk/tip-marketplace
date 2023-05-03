import json

from TIPCommon import extract_configuration_param, extract_action_param

from GoogleCloudIAMManager import GoogleCloudIAMManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    CREATE_ROLE_SCRIPT_NAME
)
from exceptions import (
    GoogleCloudIAMRoleJSONError,
    GoogleCloudIAMRoleExistsError,
    GoogleCloudIAMRoleIDInvalidError
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {CREATE_ROLE_SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    account_type = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Account Type",
        print_value=True
    )
    project_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Project ID",
        print_value=True
    )
    private_key_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Private Key ID",
        remove_whitespaces=False
    )
    private_key = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Private Key",
        remove_whitespaces=False
    )
    client_email = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client Email",
        print_value=True
    )
    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client ID",
        print_value=True
    )
    auth_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Auth URI",
        print_value=True
    )
    token_uri = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Token URI",
        print_value=True
    )
    auth_provider_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Auth Provider X509 URL",
        print_value=True
    )
    client_x509_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Client X509 URL",
        print_value=True
    )
    service_account_json = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Service Account Json File Content",
        remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_IDENTIFIER,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )

    # Action configuration
    role_id = extract_action_param(siemplify, param_name="Role ID", is_mandatory=True, print_value=True)
    role_definition_json = extract_action_param(siemplify, param_name="Role Definition", is_mandatory=True, print_value=True)
    role_definition_param = role_definition_json

    # Action results
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        try:
            role_definition_json = json.loads(role_definition_json)
        except Exception as error:
            raise GoogleCloudIAMRoleJSONError(error)

        manager = GoogleCloudIAMManager(
            account_type=account_type,
            project_id=project_id,
            private_key_id=private_key_id,
            private_key=private_key,
            client_email=client_email,
            client_id=client_id,
            auth_uri=auth_uri,
            token_uri=token_uri,
            auth_provider_x509_url=auth_provider_x509_url,
            client_x509_cert_url=client_x509_url,
            service_account_json=service_account_json,
            verify_ssl=verify_ssl
        )
        created_role = manager.create_projects_role(role_id=role_id, role_definition_json=role_definition_json)
        siemplify.result.add_result_json(created_role.to_json())
        output_message = f"{INTEGRATION_DISPLAY_NAME} {role_id} was created successfully."
        result_value = True

    except GoogleCloudIAMRoleIDInvalidError as error:
        output_message = f"{error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except GoogleCloudIAMRoleExistsError as error:
        output_message = f"Provided role id {role_id} already exists."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except GoogleCloudIAMRoleJSONError as error:
        output_message = f"Provided role definition JSON document {role_definition_param} is not valid."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except Exception as error:
        output_message = f"Error executing action \"{CREATE_ROLE_SCRIPT_NAME}\". Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
