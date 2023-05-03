from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Create Isolate Machine Task'.format(PROVIDER_NAME)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Api Root",
        input_type=unicode,
        is_mandatory=True
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client ID",
        input_type=unicode,
        is_mandatory=True
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
        is_mandatory=True
    )

    tenant_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Azure Active Directory ID",
        input_type=unicode,
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True,
        default_value=False
    )

    isolation_type = extract_action_param(
        siemplify,
        param_name="Isolation Type",
        input_type=unicode,
        is_mandatory=True
    )

    comment = extract_action_param(
        siemplify,
        param_name="Comment",
        input_type=unicode,
        is_mandatory=True
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Validation block
    validation_errors = []

    try:
        MicrosoftDefenderATPManager.validate_isolation_type(isolation_type)
    except MicrosoftDefenderATPValidationError as e:
        validation_errors.append(e.message)

    if validation_errors:
        siemplify.end(
            MicrosoftDefenderATPManager.join_validation_errors(validation_errors),
            u'false',
            EXECUTION_STATE_FAILED
        )

    try:
        microsoft_defender_atp = MicrosoftDefenderATPManager(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            resource=api_root,
            verify_ssl=verify_ssl
        )

        tasks = []
        succeeded_entities = set()
        missing_entities = set()
        failed_entities = set()
        output_messages = []

        for entity in siemplify.target_entities:
            siemplify.LOGGER.info(u'Start processing entity {}'.format(entity.identifier))

            try:
                if entity.entity_type == EntityTypes.HOSTNAME:
                    machines = microsoft_defender_atp.get_machines_by_name(starts_with_name=entity.identifier)
                elif entity.entity_type == EntityTypes.ADDRESS:
                    machines = microsoft_defender_atp.get_machines(ip=entity.identifier)
                else:
                    siemplify.LOGGER.info(u'Entity {} is of unsupported type {}, skipping...'.format(
                        entity.identifier, entity.entity_type
                    ))
                    continue
            except MicrosoftDefenderATPError as e:
                siemplify.LOGGER.error(u'Error occurred: {}'.format(e))
                siemplify.LOGGER.exception(e)
                failed_entities.add(entity)
                continue

            if not machines:
                msg = u'Failed to find machine ATP by {} entity with type {}'.format(
                    entity.identifier, entity.entity_type
                )
                output_messages.append(msg)
                siemplify.LOGGER.warn(msg)
                missing_entities.add(entity)
                continue

            siemplify.LOGGER.info(u'Found {} machines for entity {}'.format(len(machines), entity.identifier))
            found_machine = machines[-1]

            try:
                siemplify.LOGGER.info(u'Initiating machine {} isolation'.format(found_machine.id))
                task = microsoft_defender_atp.isolate_machine(
                    machine_id=found_machine.id,
                    isolation_type=isolation_type,
                    comment=comment
                )
                tasks.append(task)
                msg = u'Isolate machine task {} was created successfully on Defender ATP Server for {}'.format(
                        task.id, entity.identifier
                )
                output_messages.append(msg)
                siemplify.LOGGER.info(msg)
                succeeded_entities.add(entity)

            except MicrosoftDefenderATPError as e:
                output_messages.append(u'Failed to process entity {}. {}'.format(entity.identifier, e))
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)
                failed_entities.add(entity)

        # To remove all failed entities from succeeded entities
        succeeded_entities = succeeded_entities & failed_entities ^ succeeded_entities

        if succeeded_entities:
            output_messages.append(u'{} entities were successfully processed'.format(len(succeeded_entities)))

        if missing_entities:
            output_messages.append(u'{} entities were not found in ATP'.format(len(missing_entities)))

        if failed_entities:
            output_messages.append(u'{} entities failed'.format(len(failed_entities)))
            output_messages.append(u'Action failed to complete successfully on the following entities: {}'.format(
                MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                    [entity.identifier for entity in failed_entities]
                )
            ))

            result = u'false'
        else:
            output_messages.append(u'Action completed successfully')
            result = u'true'

        if tasks:
            siemplify.result.add_result_json([task.to_json() for task in tasks])

            siemplify.result.add_data_table(
                title=u'Created Defender ATP isolate machine tasks:',
                data_table=construct_csv([task.to_table() for task in tasks])
            )

        output_message = u'\n'.join(output_messages)
        status = EXECUTION_STATE_COMPLETED

    except MicrosoftDefenderATPError as e:
        output_message = u'Action didn\'t completed due to error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
