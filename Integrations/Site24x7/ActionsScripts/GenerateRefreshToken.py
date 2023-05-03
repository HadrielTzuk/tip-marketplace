from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GENERATE_REFRESH_TOKEN_SCRIPT_NAME
from Site24x7Manager import Site24x7Manager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GENERATE_REFRESH_TOKEN_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_configuration_param(
        siemplify=siemplify,
        param_name='Client ID',
        is_mandatory=True,
        provider_name=INTEGRATION_NAME,
        print_value=True
    )

    client_secret = extract_configuration_param(
        siemplify=siemplify,
        param_name='Client Secret',
        is_mandatory=True,
        provider_name=INTEGRATION_NAME,
        print_value=False
    )

    auth_code = extract_action_param(
        siemplify=siemplify,
        param_name="Authorization Code",
        is_mandatory=True,
        print_value=False
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        refresh_token = Site24x7Manager.generate_refresh_token(api_root=api_root,
                                                               client_id=client_id,
                                                               client_secret=client_secret,
                                                               code=auth_code)
        output_message = "Successfully generated the refresh token. Copy that refresh token and put it in the " \
                         "Integration configuration."
        siemplify.result.add_result_json({"refresh_token": f"{refresh_token}"})

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"Generate Refresh Token\". Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Status: {status}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
