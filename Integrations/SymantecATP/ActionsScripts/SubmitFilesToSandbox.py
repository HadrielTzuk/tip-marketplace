from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from SiemplifyDataModel import EntityTypes
from SymantecATPManager import ATPEntityTypes


ATP_PROVIDER = 'SymantecATP'
ACTION_NAME = "SymantecATP_Submit File To Sandbox"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    errors = []
    command_ids = []
    submitted_entities = []

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.FILEHASH and atp_manager.is_hash_sha256(entity.identifier):
                command_id = atp_manager.submit_file_to_sandbox(entity.identifier)
                command_ids.append(command_id)
                submitted_entities.append(entity)
        except Exception as err:
            error_message = 'Error submitting file "{0}" to sandbox, Error: {1}'.format(
                entity.identifier, err.message)
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if submitted_entities:
        output_message = "{0} were submitted to sandbox.".format(",".join([entity.identifier for entity in
                                                                           submitted_entities]))
    else:
        output_message = "No file hashes were submitted to sandbox."

    # Attach errors if exists.
    if errors:
        output_message = "{0},\n\nERRORS:\n{1}".format(output_message, ' \n '.join(errors))

    siemplify.end(output_message, ",".join(command_ids))


if __name__ == "__main__":
    main()
