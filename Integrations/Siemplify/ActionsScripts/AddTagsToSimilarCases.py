from TIPCommon import extract_action_param

from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


# from SiemplifyMock import SiemplifyActionMock

def valdiate_bool_param(siemplify, param_name, default_value):
    return str(siemplify.parameters.get(param_name, default_value)).lower() == str(True).lower()


@output_handler
def main():
    siemplify = SiemplifyAction()
    # siemplify = SiemplifyActionMock()
    siemplify.script_name = "AddTagsToSimilarCases"

    # This action MUST run in alert scope
    if not siemplify.current_alert:
        siemplify.end("This action can't run manually.", 'false')

    consider_ports = valdiate_bool_param(siemplify, "Port", True)
    consider_category_outcome = valdiate_bool_param(siemplify, "Category Outcome", True)
    consider_rule_generator = valdiate_bool_param(siemplify, "Rule Generator", True)
    consider_entity_identifiers = valdiate_bool_param(siemplify, "Entity Identifier", True)
    days_to_look_back = siemplify.parameters.get("Days Back", None)
    tags = extract_action_param(siemplify, param_name="Tags",
                                print_value=False, is_mandatory=True, default_value=None)

    tags = [tag.strip() for tag in tags.split(',')] if tags else []

    similarCases = siemplify.get_similar_cases(consider_ports=consider_ports,
                                               consider_category_outcome=consider_category_outcome,
                                               consider_rule_generator=consider_rule_generator,
                                               consider_entity_identifiers=consider_entity_identifiers,
                                               days_to_look_back=days_to_look_back)

    failed_cases = set()  # cases that failed to add tag to
    failed_tags = set()  # tag that failed to be added
    successful_cases = set()  # cases that where successfully added with tags
    successful_tags = set()  # tags that were successfully added to case

    if tags:
        siemplify.LOGGER.info("Adding tags '{}' to cases with ids {}".format(', '.join(tags), similarCases))
        for case_id in similarCases:
            case = siemplify._get_case_by_id(case_id)
            case_alert_identifier = case.get("cyber_alerts", {})[0].get("identifier")
            for tag in tags:
                try:
                    siemplify.add_tag(tag=str(tag), case_id=str(case_id),
                                      alert_identifier=case_alert_identifier)
                    successful_cases.add(case_id)
                    successful_tags.add(tag)
                except Exception as e:
                    failed_cases.add(case_id)
                    failed_tags.add(tag)
                    siemplify.LOGGER.error("Failed to add tag {} to case {}".format(tag, case_id))
                    siemplify.LOGGER.exception(e)

    if (len(similarCases) == 0):
        output_message = "No similar cases Found"
    else:
        similarCases.sort(key=int)
        output_message = "\n\nFound {0} similar cases: {1}".format(str(len(similarCases)), str(similarCases))

    if failed_cases:
        output_message += "\n\nFailed to add tags: {} to cases {}".format(', '.join(list(failed_tags)),
                                                                          list(failed_cases))

    if successful_cases:
        output_message += "\n\nSuccessfully added tags: {} to cases {}".format(', '.join(list(successful_tags)),
                                                                               list(successful_cases))

    siemplify.LOGGER.info(output_message)
    siemplify.end(output_message, str(similarCases))


if __name__ == '__main__':
    main()
