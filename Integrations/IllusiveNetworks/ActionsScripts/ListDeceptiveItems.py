from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IllusiveNetworksManager import IllusiveNetworksManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    PRODUCT_NAME,
    LIST_DECEPTIVE_ITEMS_ACTION,
    ALL,
    ONLY_USERS,
    ONLY_SERVERS,
    DECEPTIVE_STATE_MAPPING,
    DECEPTIVE_USERS_TABLE_NAME,
    DECEPTIVE_SERVERS_TABLE_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_DECEPTIVE_ITEMS_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True, print_value=False)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='CA Certificate File')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool, is_mandatory=True)

    deceptive_type = extract_action_param(siemplify, param_name='Deceptive Type', print_value=True, default_value=ALL)
    deceptive_state = extract_action_param(siemplify, param_name='Deceptive State', print_value=True, default_value=ALL)
    max_items_to_return = extract_action_param(siemplify, param_name='Max Items To Return', print_value=True,
                                               input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = f"Successfully returned available deceptive items from {PRODUCT_NAME}."
    deceptive_users, deceptive_servers = [], []

    try:
        manager = IllusiveNetworksManager(api_root=api_root, api_key=api_key, ca_certificate=ca_certificate,
                                          verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        if deceptive_type == ALL or deceptive_type == ONLY_USERS:
            deceptive_users = manager.get_deceptive_users(deceptive_state=DECEPTIVE_STATE_MAPPING[deceptive_state],
                                                          limit=max_items_to_return)
        if deceptive_type == ALL or deceptive_type == ONLY_SERVERS:
            deceptive_servers = manager.get_deceptive_servers(deceptive_state=DECEPTIVE_STATE_MAPPING[deceptive_state],
                                                              limit=max_items_to_return)

        if deceptive_users:
            siemplify.result.add_data_table(DECEPTIVE_USERS_TABLE_NAME,
                                            construct_csv([user.to_table() for user in deceptive_users]))
        if deceptive_servers:
            siemplify.result.add_data_table(DECEPTIVE_SERVERS_TABLE_NAME,
                                            construct_csv([server.to_table() for server in deceptive_servers]))

        if deceptive_users or deceptive_servers:
            json_results = {
                'users': [user.to_json() for user in deceptive_users],
                'servers': [server.to_json() for server in deceptive_servers]
            }
            siemplify.result.add_result_json(json_results)
        else:
            output_message = f"No data was found regarding deceptive items based on the provided criteria in " \
                             f"{PRODUCT_NAME}."
            result_value = False

    except Exception as err:
        output_message = "Error executing action '{}'. Reason: {}".format(LIST_DECEPTIVE_ITEMS_ACTION, err)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
