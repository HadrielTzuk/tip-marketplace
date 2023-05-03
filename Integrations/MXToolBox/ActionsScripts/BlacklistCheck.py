from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from MXToolBoxManager import MXToolBoxManager
from SiemplifyUtils import construct_csv, get_domain_from_entity, convert_dict_to_json_result_dict

MXTOOLBOX_PROVIDER = 'MXToolBox'
SCRIPT_NAME = 'MXToolBox_DNS_Lookup'
INSIGHT_MESSAGE = '{0} was found in {1} blacklist.'


@output_handler
def main():
    # Configurations.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration(MXTOOLBOX_PROVIDER)
    verify_ssl = conf['Verify SSL'].lower() == 'true'
    mx_tool_box_manager = MXToolBoxManager(conf['API Root'], conf['API Key'], verify_ssl)

    # Variables.
    errors = []
    success_entities = []
    blacklists_amount_for_entity = {}
    result_value = False
    failed_results = []
    json_results = {}

    # Parameters.
    blacklilst_threshold = siemplify.parameters.get('Blacklist Threshold')

    target_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME or
                       entity.entity_type == EntityTypes.ADDRESS]

    for entity in target_entities:
        try:
            result = mx_tool_box_manager.domain_blacklist_lookup(get_domain_from_entity(entity))
            if result:
                if result.get('Failed'):
                    json_results[entity.identifier] = result.get("Failed")

                    for record in result.get('Failed'):
                        failed_results.append({"Engine Name": record.get("Name"),
                                               "Blacklisted Reason": record.get("BlacklistReasonDescription")})
                    siemplify.result.add_entity_table(entity.identifier, construct_csv(failed_results))
                    blacklist_detected_amount = len(result.get('Failed'))
                    if int(blacklilst_threshold) >= blacklist_detected_amount:
                        entity.is_suspicious = True
                        blacklists_amount_for_entity[entity] = blacklist_detected_amount
                        result_value = True
                success_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            error_message = "An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e))
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(e)
            errors.append(error_message)

    if success_entities:
        output_message = "The following IPs were submitted and analyzed: {0}".format(
            ", ".join([entity.identifier for entity in success_entities]))
        siemplify.update_entities(success_entities)

        for entity, blacklist_detected_amount in blacklists_amount_for_entity.items():
            siemplify.add_entity_insight(entity,
                                         INSIGHT_MESSAGE.format(entity.identifier, blacklist_detected_amount),
                                         MXTOOLBOX_PROVIDER)
    else:
        output_message = 'Not found data for target entities.'

    if errors:
        output_message = "{0}  \n \n {1}".format(output_message, " \n ".join(errors))

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
