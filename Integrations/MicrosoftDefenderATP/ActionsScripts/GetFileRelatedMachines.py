from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from MicrosoftDefenderATPManager import MicrosoftDefenderATPManager, MicrosoftDefenderATPError, \
    MicrosoftDefenderATPValidationError

PROVIDER_NAME = u'MicrosoftDefenderATP'
SCRIPT_NAME = u'{} - Get File Related Machines'.format(PROVIDER_NAME)


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

    name = extract_action_param(
        siemplify,
        param_name="Machine Name",
        input_type=unicode,
        is_mandatory=False
    )

    ip = extract_action_param(
        siemplify,
        param_name="Machine IP Address",
        input_type=unicode,
        is_mandatory=False
    )

    risk_scores = extract_action_param(
        siemplify,
        param_name="Machine Risk Score",
        input_type=unicode,
        is_mandatory=False
    )

    health_statuses = extract_action_param(
        siemplify,
        param_name="Machine Health Status",
        input_type=unicode,
        is_mandatory=False
    )

    os_platform = extract_action_param(
        siemplify,
        param_name="Machine OS Platform",
        input_type=unicode,
        is_mandatory=False
    )

    rbac_group_id = extract_action_param(
        siemplify,
        param_name="RBAC Group ID",
        input_type=int,
        is_mandatory=False
    )

    health_statuses = MicrosoftDefenderATPManager.convert_comma_separated_to_list(health_statuses)
    risk_scores = MicrosoftDefenderATPManager.convert_comma_separated_to_list(risk_scores)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    # Validation block
    validation_errors = []

    if health_statuses:
        try:
            MicrosoftDefenderATPManager.validate_health_statuses(*health_statuses)
        except MicrosoftDefenderATPValidationError as e:
            validation_errors.append(e.message)

    if risk_scores:
        try:
            MicrosoftDefenderATPManager.validate_risk_scores(*risk_scores)
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

        succeeded_entities = []
        missed_entities = []
        failed_entities = []
        output_messages = []
        json_results = {}

        for entity in siemplify.target_entities:
            siemplify.LOGGER.info(u'Start processing entity {}'.format(entity.identifier))

            try:
                if entity.entity_type == EntityTypes.FILEHASH:
                    machines = microsoft_defender_atp.get_file_related_machines(
                        file_hash=entity.identifier,
                        name=name,
                        ip=ip,
                        risk_scores=risk_scores,
                        health_statuses=health_statuses,
                        os_platform=os_platform,
                        rbac_group_id=rbac_group_id
                    )
                else:
                    siemplify.LOGGER.info(u'Entity {} is of unsupported type {}, skipping...'.format(
                        entity.identifier, entity.entity_type
                    ))
                    continue
            except MicrosoftDefenderATPError as e:
                output_messages.append(u'Failed to process entity {}. {}'.format(entity.identifier, e))
                failed_entities.append(entity)
                siemplify.LOGGER.info(u'Processing {} entity failed'.format(entity.identifier))
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)
                continue

            json_results[entity.identifier] = [machine.to_json() for machine in machines]

            if not machines:
                missed_entities.append(entity)
            else:
                succeeded_entities.append(entity)
                siemplify.LOGGER.info(u'Processing {} entity succeeded'.format(entity.identifier))

                siemplify.result.add_entity_json(
                    entity_identifier=entity.identifier,
                    json_data=[machine.to_json() for machine in machines]
                )

                siemplify.result.add_entity_table(
                    entity_identifier=entity.identifier,
                    data_table=construct_csv([machine.to_table() for machine in machines])
                )

            output_messages.append(u'{} machines found for entity {}'.format(
                u'No' if not machines else len(machines), entity.identifier
            ))

            siemplify.LOGGER.info(u'Finish processing entity {}'.format(entity.identifier))

        if succeeded_entities:
            output_messages.append(u'{} entities were successfully processed'.format(len(succeeded_entities)))

        if missed_entities:
            output_messages.append(u'{} entities were not found in ATP'.format(len(missed_entities)))

        if failed_entities:
            output_messages.append(u'{} entities failed'.format(len(failed_entities)))
            output_messages.append(u'Action failed to complete successfully on the following entities: {}'.format(
                MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                    [entity.identifier for entity in failed_entities]
                )
            ))

            result = u'false'
        else:
            result = u'true'

        output_message = u'\n'.join(output_messages)
        status = EXECUTION_STATE_COMPLETED

    except MicrosoftDefenderATPError as e:
        output_message = u'Action didn\'t completed due to error: {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
