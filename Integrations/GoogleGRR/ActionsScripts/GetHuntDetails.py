import utils

from GoogleGRRManager import GoogleGRRManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, HUNT_URL_PART, GET_HUNT_DETAILS
from exceptions import GoogleGRRNotFoundException, GoogleGRRInvalidCredentialsException, GoogleGRRNotConnectedException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, GET_HUNT_DETAILS)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Username',
        is_mandatory=True,
        print_value=True
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Password',
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Verify SSL',
        input_type=bool,
        is_mandatory=False,
        print_value=True
    )

    hunt_ids = extract_action_param(
        siemplify,
        param_name="Hunt ID",
        is_mandatory=True,
        input_type=str,
        print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_results = []
    result_value = False
    output_message = ''
    invalid_hunts = []
    valid_hunts = []

    try:
        manager = GoogleGRRManager(api_root=api_root,
                                   username=username,
                                   password=password,
                                   verify_ssl=verify_ssl)

        #  Get list of hunt ids from hunts comma separated value
        hunt_ids = utils.load_csv_to_list(hunt_ids, "Hunt ID")

        siemplify.LOGGER.info("Start processing hunts")
        for hunt_id in hunt_ids:
            try:
                siemplify.LOGGER.info(f"Fetching hunt with id: {hunt_id}")
                hunt = manager.get_hunt_details(hunt_id=hunt_id)
                siemplify.LOGGER.info(f"Successfully fetched hunt with id: {hunt_id}")

                valid_hunts.append(hunt_id)
                json_results.append(hunt.as_json_by_id())
                siemplify.result.add_link(f'Hunt {hunt_id} Link: ', f'{api_root}{HUNT_URL_PART}{hunt_id}')

            except GoogleGRRNotFoundException as e:
                invalid_hunts.append(hunt_id)
                siemplify.LOGGER.info(f"Failed to fetch hunt with id: {hunt_id}. Error: {e}")
                siemplify.LOGGER.error(f"Failed to fetch hunt with id: {hunt_id}. Error: {e}")
                siemplify.LOGGER.error(e)
        siemplify.LOGGER.info("Finished processing hunts")

        if valid_hunts:
            siemplify.result.add_result_json(json_results)
            output_message += f"Successfully fetched details for hunts with ids: {', '.join(valid_hunts)} .\n"
            result_value = True

        if invalid_hunts:
            output_message += f"Could not fetch details for the specified hunts: {', '.join(invalid_hunts)} " \
                              f"don't exist in GRR.\n"

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f'Error executing action “Get Hunt Details”! Error is {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()


