from CynetManager import CynetManager
# Imports
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param

# Consts
FILEHASH = EntityTypes.FILEHASH
INTEGRATION_NAME = "Cynet"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Cynet - KillHashInHosts"
    hash_report = {}
    remediation_hosts_dict = {}
    quarantine_hosts = []
    results_json = {}

    # Configuration.
    conf = siemplify.get_configuration("Cynet")
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    cynet_manager = CynetManager(api_root, username, password, verify_ssl)

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == FILEHASH:
                hash_lower = entity.identifier.lower()
                # Define if file hash type is sha256 or not
                is_sha256 = cynet_manager.is_sha256(hash_lower)

                if is_sha256:
                    hash_report = cynet_manager.get_hash_details(hash_lower)

                if hash_report.get("occurrences"):
                    for occurrence in hash_report["occurrences"]:
                        host_name = occurrence.get("hostname")
                        if host_name not in quarantine_hosts:
                            r = cynet_manager.kill_file_remediation(hash_lower, host_name)
                            remediation_items = r.get("remediation_items")
                            quarantine_hosts.append(host_name)
                            remediation_items_id = remediation_items[0] # *******************
                            results_json[entity.identifier] = remediation_items_id
                            remediation_status = cynet_manager.get_remediation_status(remediation_items_id)
                            remediation_status_info = remediation_status.get("statusInfo")
                            remediation_hosts_dict.update({host_name: remediation_items_id})

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            siemplify.LOGGER.exception(e)

    if remediation_hosts_dict:
        output_message = 'Kill process file remediation action status for {0}\n'.format(hash_lower)
        for hostname, remediation_id in remediation_hosts_dict.items():
            output_message += "Hostname: {0}, Remidation Id: {1}\n".format(hostname, remediation_id)
        result_value = 'true'
    else:
        output_message = 'Could not find results.'
        result_value = 'false'

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(results_json))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
