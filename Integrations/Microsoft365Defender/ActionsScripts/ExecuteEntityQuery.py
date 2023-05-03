from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from Microsoft365DefenderManager import Microsoft365DefenderManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, EXECUTE_ENTITY_QUERY_SCRIPT_NAME, \
    DEFAULT_RESULTS_LIMIT
from UtilsManager import get_timestamps, convert_comma_separated_to_list, check_if_key_provided, get_email_address
from Microsoft365DefenderExceptions import NotEnoughEntitiesException

TABLE_NAME = "Results"
SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME, EntityTypes.USER, EntityTypes.FILEHASH,
                          EntityTypes.URL]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_ENTITY_QUERY_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant ID",
                                            is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    table_names = extract_action_param(siemplify, param_name="Table Names", is_mandatory=True, print_value=True)
    timeframe = extract_action_param(siemplify, param_name="Time Frame", print_value=True)
    start_time_string = extract_action_param(siemplify, param_name="Start Time", print_value=True)
    end_time_string = extract_action_param(siemplify, param_name="End Time", print_value=True)
    fields_to_return = extract_action_param(siemplify, param_name="Fields To Return", print_value=True)
    sort_field = extract_action_param(siemplify, param_name="Sort Field", print_value=True)
    sort_order = extract_action_param(siemplify, param_name="Sort Order", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Results To Return", input_type=int, print_value=True,
                                 default_value=DEFAULT_RESULTS_LIMIT)
    ip_entity_key = extract_action_param(siemplify, param_name="IP Entity Key", print_value=True)
    hostname_entity_key = extract_action_param(siemplify, param_name="Hostname Entity Key", print_value=True)
    file_hash_entity_key = extract_action_param(siemplify, param_name="File Hash Entity Key", print_value=True)
    user_entity_key = extract_action_param(siemplify, param_name="User Entity Key", print_value=True)
    url_entity_key = extract_action_param(siemplify, param_name="URL Entity Key", print_value=True)
    email_address_entity_key = extract_action_param(siemplify, param_name="Email Address Entity Key", print_value=True)
    stop_if_not_enough_entities = extract_action_param(siemplify, param_name="Stop If Not Enough Entities",
                                                       input_type=bool, print_value=True, is_mandatory=True)
    cross_operator = extract_action_param(siemplify, param_name="Cross Entity Operator", is_mandatory=True,
                                          print_value=True)

    table_names = convert_comma_separated_to_list(table_names)
    fields_to_return = convert_comma_separated_to_list(fields_to_return)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = False
    status = EXECUTION_STATE_COMPLETED
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    ip_entities, hostname_entities, file_hash_entities, user_entities, url_entities, email_entities = [], [], [], [], \
                                                                                                      [], []

    try:
        if limit < 1:
            raise Exception("\"Max Results To Return\" must be greater than 0.")

        start_time, end_time = get_timestamps(timeframe, start_time_string, end_time_string)

        for entity in suitable_entities:
            if entity.entity_type == EntityTypes.ADDRESS:
                ip_entities.append(entity.identifier)
            elif entity.entity_type == EntityTypes.HOSTNAME:
                hostname_entities.append(entity.identifier)
            elif entity.entity_type == EntityTypes.USER:
                if get_email_address(entity):
                    email_entities.append(entity.identifier)
                else:
                    user_entities.append(entity.identifier)
            elif entity.entity_type == EntityTypes.FILEHASH:
                file_hash_entities.append(entity.identifier)
            elif entity.entity_type == EntityTypes.URL:
                url_entities.append(entity.identifier)

        if stop_if_not_enough_entities:
            all_key_entities_pairs = {ip_entity_key: ip_entities, hostname_entity_key: hostname_entities,
                                      file_hash_entity_key: file_hash_entities, user_entity_key: user_entities,
                                      url_entity_key: url_entities, email_address_entity_key: email_entities}
            for key, value in all_key_entities_pairs.items():
                check_if_key_provided(key, value)

        manager = Microsoft365DefenderManager(api_root=api_root, tenant_id=tenant_id, client_id=client_id,
                                              client_secret=client_secret, verify_ssl=verify_ssl,
                                              siemplify=siemplify)

        query_string = manager.build_query_string(
            ip_key=ip_entity_key,
            hostname_key=hostname_entity_key,
            hash_key=file_hash_entity_key,
            user_key=user_entity_key,
            url_key=url_entity_key,
            email_key=email_address_entity_key,
            cross_entity_operator=cross_operator,
            ip_entities=ip_entities,
            hostname_entities=hostname_entities,
            hash_entities=file_hash_entities,
            user_entities=user_entities,
            url_entities=url_entities,
            email_entities=email_entities)

        devices, query_string = manager.search_for_devices(
            table_names=table_names,
            start_time=start_time,
            end_time=end_time,
            user_query=query_string,
            fields=fields_to_return,
            sort_field=sort_field,
            sort_order=sort_order.lower(),
            limit=limit
        )

        if devices:
            result = True
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([device.to_csv() for device in devices]))
            siemplify.result.add_result_json([device.to_json() for device in devices])
            output_message = f"Successfully executed query \"{query_string}\" in {INTEGRATION_DISPLAY_NAME}" if \
                query_string else f"Successfully executed query in {INTEGRATION_DISPLAY_NAME}"
        else:
            output_message = f"No data was found for the query \"{query_string}\" in {INTEGRATION_DISPLAY_NAME}" if \
                query_string else f"No data was found for the query in {INTEGRATION_DISPLAY_NAME}"

    except NotEnoughEntitiesException as e:
        output_message = str(e)

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {EXECUTE_ENTITY_QUERY_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"Execute Entity Query.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
