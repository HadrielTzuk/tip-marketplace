from SiemplifyUtils import output_handler, add_prefix_to_dict_keys, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, construct_csv, extract_action_param
from ThreatQManager import ThreatQManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
import re
from constants import STATUS_MAPPING

# =====================================
#             CONSTANTS               #
# =====================================
THREATQ_PREFIX = u"TQ"

INTEGRATION_NAME = u"ThreatQ"
SCRIPT_NAME = u"ThreatQ - Enrich Email"
EMAIL_REGEX = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,63}$"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # Variables Definitions.
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED
    output_message = u""

    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress",
        input_type=unicode
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId",
        input_type=unicode
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username",
        input_type=unicode
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password",
        input_type=unicode
    )

    score_threshold = extract_action_param(
        siemplify=siemplify,
        param_name='Score Threshold',
        input_type=int,
        print_value=True,
        is_mandatory=False
    )

    show_sources = extract_action_param(
        siemplify=siemplify,
        param_name='Show Sources',
        input_type=bool,
        print_value=True,
        is_mandatory=False
    )

    show_comments = extract_action_param(
        siemplify=siemplify,
        param_name='Show Comments',
        input_type=bool,
        print_value=True,
        is_mandatory=False
    )

    show_attributes = extract_action_param(
        siemplify=siemplify,
        param_name='Show Attributes',
        input_type=bool,
        print_value=True,
        is_mandatory=False
    )

    mark_whitelisted_entities_as_suspicious = extract_action_param(
        siemplify=siemplify,
        param_name='Mark Whitelisted Entities As Suspicious',
        input_type=bool,
        print_value=True
    )

    # Threshold should be in range from 0 to 10
    score_threshold = min(max(score_threshold, 0), 10)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    entities_to_update = []
    failed_entities = []
    json_results = {}
    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        for entity in siemplify.target_entities:
            try:
                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                # check if entity is email address
                if not re.search(EMAIL_REGEX, entity.identifier):
                    continue

                email_obj = threatq_manager.get_email_object(entity.identifier)
                if email_obj is None:
                    siemplify.LOGGER.info(u"No Email details ware found for entity: {}".format(entity.identifier))
                    failed_entities.append(entity)
                    continue

                if email_obj.indicator_score > score_threshold \
                        and (mark_whitelisted_entities_as_suspicious
                             or email_obj.indicator_status_id != STATUS_MAPPING.get('Whitelisted')):
                    entity.is_suspicious = True

                json_results[entity.identifier] = email_obj.to_json()
                entity.additional_properties.update(add_prefix_to_dict_keys(email_obj.to_flat_dict(), THREATQ_PREFIX))
                entities_to_update.append(entity)

                # Case Wall
                flat_comments = email_obj.comments_table()
                if flat_comments and show_comments:
                    siemplify.LOGGER.info(
                        u"Found {} comments for entity: {}".format(len(flat_comments), entity.identifier))
                    siemplify.result.add_entity_table(u"{} - Comments".format(entity.identifier),
                                                      construct_csv(flat_comments))

                flat_attributes = email_obj.attributes_table()
                if flat_attributes and show_attributes:
                    siemplify.LOGGER.info(
                        u"Found {} attributes for entity: {}".format(len(flat_attributes), entity.identifier))
                    siemplify.result.add_entity_table(u"{} - Attributes".format(entity.identifier),
                                                      construct_csv(flat_attributes))

                flat_sources = email_obj.sources_table()
                if flat_sources and show_sources:
                    siemplify.LOGGER.info(
                        u"Found {} sources for entity: {}".format(len(flat_sources), entity.identifier))
                    siemplify.result.add_entity_table(u"{} - Sources".format(entity.identifier),
                                                      construct_csv(flat_sources))

                siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))

            except Exception as e:
                output_message += u"Unable to enrich entity: {} \n".format(entity.identifier)
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"Failed processing entity:{}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if entities_to_update:
            siemplify.update_entities(entities_to_update)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message = u"Successfully enriched email address:\n{0}".format(u", ".join([entity.identifier for entity in
                                                                             entities_to_update]))
            result_value = u"true"

        else:
            output_message = u"Email addresses were not enriched."
            result_value = u"false"

        if failed_entities:
            output_message += u"\nFailed to enrich the following entities:\n{0}".format(
                u"\n".join([entity.identifier for entity in
                            failed_entities]))

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
