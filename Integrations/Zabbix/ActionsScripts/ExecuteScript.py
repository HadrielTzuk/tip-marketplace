from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import create_entity_json_result_object, output_handler
from ZabbixManager import ZabbixManager, EXECUTION_FAILED, EXECUTION_SUCCEEDED
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Zabbix - ExecuteScript"

    configurations = siemplify.get_configuration('Zabbix')
    server_addr = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']
    verify_ssl = configurations.get('Verify SSL', 'False').lower() == 'true'

    zabbix = ZabbixManager(server_addr, username, password, verify_ssl)

    script_name = siemplify.parameters["Script Name"]
    script = zabbix.get_script_by_name(script_name)

    output_message = ""
    success_entities = []
    failed_entities = []
    missing_entities = []
    json_results = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS:
            try:
                hosts = zabbix.get_hosts_by_ip(entity.identifier)

                siemplify.LOGGER.info(
                    "Found {} hosts with IP {}.".format(
                        len(hosts),
                        entity.identifier
                    )
                )

                if hosts:
                    for host in hosts:
                        host_id = host.get("hostid")

                        siemplify.LOGGER.info(
                            "Executing script {} on host {}.".format(
                                script_name, host_id)
                        )

                        result = zabbix.execute_script(
                            host_id,
                            script.get("scriptid")
                        )

                        json_results.append(
                            create_entity_json_result_object(
                                entity.identifier,
                                result
                            )
                        )

                        if result.get("response") == EXECUTION_FAILED:
                            siemplify.LOGGER.error(
                                "Failed to run script {} on host {}. Script output: {}".format(
                                    script_name,
                                    host_id,
                                    result.get("value")
                                )
                            )
                            failed_entities.append(entity.identifier)

                        elif result.get("response") == EXECUTION_SUCCEEDED:
                            siemplify.LOGGER.info(
                                "Script {} completed on host {}. Script output: {}".format(
                                    script_name,
                                    host_id,
                                    result.get("value")
                                )
                            )
                            success_entities.append(entity.identifier)

                        else:
                            siemplify.LOGGER.error(
                                "Script {} execution on host {} ended with unknown status. Script output: {}".format(
                                    script_name,
                                    host_id,
                                    result.get("value")
                                )
                            )
                            failed_entities.append(entity.identifier)

                else:
                    siemplify.LOGGER.info(
                        "Couldn't find host with IP {}.".format(
                            entity.identifier)
                    )
                    missing_entities.append(entity.identifier)

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(
                    "An error occurred on entity: {}.\n{}.".format(
                        entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                failed_entities.append(entity)

    if success_entities:
        output_message = 'Script {} execution succeeded on the following entities:\n{}\n'.format(
            script_name,
            "\n".join(success_entities),
        )

    if failed_entities:
        output_message += 'The script {} failed for the following entities:\n{}\n'.format(
            script_name,
            "\n".join(failed_entities),
        )
    if missing_entities:
        output_message += 'No hosts were found for the following entitied:\n{}'.format(
            "\n".join(missing_entities),
        )

    if success_entities:
        result_value = 'true'
    else:
        result_value = 'false'

    # add json
    siemplify.result.add_result_json(json.dumps(json_results))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
