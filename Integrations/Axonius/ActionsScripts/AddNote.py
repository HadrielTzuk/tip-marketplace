import requests
from TIPCommon import extract_configuration_param, extract_action_param

from AxoniusManager import AxoniusManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import (
    INTEGRATION_IDENTIFIER,
    ADD_NOTE_SCRIPT_NAME
)
from exceptions import (
    AxoniusAuthorizationError,
    AxoniusForbiddenError
)
from utils import (
    is_valid_email
)

# Fix misalignment of MAC entity type
EntityTypes.MACADDRESS = EntityTypes.MACADDRESS.upper()
SUPPORTED_ENTITIES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS, EntityTypes.MACADDRESS, EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_IDENTIFIER, ADD_NOTE_SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='API Root', is_mandatory=True,
                                           print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='API Key', is_mandatory=True,
                                          print_value=True)
    secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='API Secret', is_mandatory=True,
                                             print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL', input_type=bool,
                                             is_mandatory=True, default_value=True, print_value=True)
    # Action parameters
    note = extract_action_param(siemplify, param_name="Note", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    devices = {
        'ip_addresses': {},  # maps entity.identifier -> entity
        'hostnames': {},
        'mac_addresses': {}
    }
    users = {
        'usernames': {},  # maps entity.identifier -> entity
        'emails': {}
    }

    found_entities_to_process = {}  # maps entity.identifier -> axonius id

    successful_entities = []
    failed_entities = []
    json_results = {}

    try:
        manager = AxoniusManager(api_root=api_root, api_key=api_key, secret_key=secret_key, verify_ssl=verify_ssl,
                                 siemplify_logger=siemplify.LOGGER)
        for entity in siemplify.target_entities:
            if entity.entity_type not in SUPPORTED_ENTITIES:
                siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                continue
            entity.identifier = entity.identifier.strip()
            if entity.entity_type == EntityTypes.USER:
                if is_valid_email(entity.identifier):
                    siemplify.LOGGER.info(f"Entity {entity.identifier} will be used as email")
                    users['emails'][entity.identifier] = entity
                else:
                    users['usernames'][entity.identifier] = entity
            elif entity.entity_type == EntityTypes.ADDRESS:
                devices['ip_addresses'][entity.identifier] = entity
            elif entity.entity_type == EntityTypes.HOSTNAME:
                devices['hostnames'][entity.identifier.upper()] = entity
            elif entity.entity_type == EntityTypes.MACADDRESS:
                devices['mac_addresses'][entity.identifier] = entity

        # process users
        if any(users.values()):
            user_entities_identifiers = list(users['usernames'].keys())
            email_entities_identifiers = list(users['emails'].keys())
            try:
                # search for axonius users
                found_users = manager.get_users(emails=email_entities_identifiers, usernames=user_entities_identifiers)
                siemplify.LOGGER.info(f"Found {len(found_users)} users in {INTEGRATION_IDENTIFIER}")

                # find missing users, match axonius ids in the response to entity identifiers
                for user in found_users:
                    # axonius user's display name correlates to siemplify user entity
                    if user.display_name in users['usernames']:
                        found_entities_to_process[user.display_name] = user.internal_axon_id
                        users['usernames'].pop(user.display_name, None)

                    # axonius user's email or username correlates to siemplify email entity
                    if user.email in users['emails']:
                        found_entities_to_process[user.email] = user.internal_axon_id
                        users['emails'].pop(user.email, None)

                    if user.username in users["emails"]:
                        found_entities_to_process[user.username] = user.internal_axon_id
                        users['emails'].pop(user.username, None)

                # mark missing entities as failed
                failed_entities.extend(list(users['usernames'].keys()) + list(users['emails'].keys()))

                for entity_identifier, axon_id in found_entities_to_process.items():
                    try:
                        siemplify.LOGGER.info(f"Adding note to {entity_identifier} with axon id {axon_id}")
                        user_note = manager.add_note_to_user(internal_axonius_id=axon_id, note=note)
                        json_results[entity_identifier] = user_note.as_json()
                        successful_entities.append(entity_identifier)
                        siemplify.LOGGER.info(f"Successfully added note to {entity_identifier}")
                    except Exception as  error:
                        failed_entities.append(entity_identifier)
                        siemplify.LOGGER.error(f"Failed to add note")
                        siemplify.LOGGER.exception(error)

            except (requests.exceptions.ConnectionError, AxoniusAuthorizationError, AxoniusForbiddenError):
                raise
            except Exception as error:
                failed_entities.extend(list(found_entities_to_process.keys()))
                siemplify.LOGGER.error(f"Failed to find users for provided entities")
                siemplify.LOGGER.exception(error)
        else:
            siemplify.LOGGER.info("Note will not be added to users")

        # process devices
        if any(devices.values()):
            found_entities_to_process = {}
            ips_entities_identifiers = list(devices['ip_addresses'].keys())
            mac_entities_identifiers = list(devices['mac_addresses'].keys())
            hostname_entities_identifiers = list(devices['hostnames'].keys())
            try:
                # search for axonius devices
                found_devices = manager.get_devices(ip_addresses=ips_entities_identifiers, mac_addresses=mac_entities_identifiers,
                                                    hostnames=hostname_entities_identifiers)
                siemplify.LOGGER.info(f"Found {len(found_devices)} devices in {INTEGRATION_IDENTIFIER}")

                # find missing devices, match axonius ids in the response to entity identifiers
                for device in found_devices:
                    for ip in device.ips:
                        if ip in devices["ip_addresses"]:
                            found_entities_to_process[ip] = device.internal_axon_id
                            devices['ip_addresses'].pop(ip, None)

                    for mac in device.macs:
                        if mac in devices['mac_addresses']:
                            found_entities_to_process[mac] = device.internal_axon_id
                            devices['mac_addresses'].pop(mac, None)

                    # axonius device's hostname and name correlates with siemplify hostname entity
                    if device.hostname in devices['hostnames']:
                        found_entities_to_process[device.hostname] = device.internal_axon_id
                        devices['hostnames'].pop(device.hostname, None)

                    if device.name in devices['hostnames']:
                        found_entities_to_process[device.name] = device.internal_axon_id
                        devices['hostnames'].pop(device.name, None)

                # mark missing entities as failed
                failed_entities.extend(list(devices['ip_addresses'].keys()) + list(devices['mac_addresses'].keys()) +
                                       list(devices['hostnames'].keys()))

                # process each entity separately
                for entity_identifier, axon_id in found_entities_to_process.items():
                    try:
                        siemplify.LOGGER.info(f"Adding note to {entity_identifier} with axon id {axon_id}")
                        device_note = manager.add_note_to_device(internal_axonius_id=axon_id, note=note)
                        json_results[entity_identifier] = device_note.as_json()
                        successful_entities.append(entity_identifier)
                        siemplify.LOGGER.info(f"Successfully added note to {entity_identifier}")
                    except Exception as error:
                        failed_entities.append(entity_identifier)
                        siemplify.LOGGER.error(f"Failed to add note")
                        siemplify.LOGGER.exception(error)

            except (requests.exceptions.ConnectionError, AxoniusAuthorizationError, AxoniusForbiddenError):
                raise
            except Exception as error:
                failed_entities.extend(list(found_entities_to_process.keys()))
                siemplify.LOGGER.error(f"Failed to find devices for provided entities")
                siemplify.LOGGER.exception(error)
        else:
            siemplify.LOGGER.info("Note will not be added to devices")

        if successful_entities:
            output_message += "Successfully added note to the following entities in {}:\n  {}\n\n".format(
                INTEGRATION_IDENTIFIER,
                "\n  ".join(successful_entities)
            )
            result_value = True
            if json_results:
                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            if failed_entities:
                output_message += "Action wasn't able to add a note to the following entities in {}:\n  {}\n\n".format(
                    INTEGRATION_IDENTIFIER,
                    "\n  ".join(failed_entities)
                )
        else:
            output_message += f"Note wasn't added to the provided entities."

    except Exception as error:
        output_message = f'Error execution action \"{ADD_NOTE_SCRIPT_NAME}\". Reason: {error}'
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
