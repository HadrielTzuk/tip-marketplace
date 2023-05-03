from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
#from SiemplifyMock import SiemplifyActionMock

def valdiate_bool_param(siemplify, param_name, default_value):
    return str(siemplify.parameters.get(param_name, default_value)).lower() == str(True).lower()

@output_handler
def main():
    siemplify = SiemplifyAction()
    #siemplify = SiemplifyActionMock()
    siemplify.script_name = "GetSimilarCases"

    # This action MUST run in alert scope
    if not siemplify.current_alert:
        siemplify.end("This action can't run manually.", 'false')

    consider_ports = valdiate_bool_param(siemplify, "Port", True)
    consider_category_outcome = valdiate_bool_param(siemplify, "Category Outcome", True)
    consider_rule_generator = valdiate_bool_param(siemplify, "Rule Generator", True)
    consider_entity_identifiers = valdiate_bool_param(siemplify, "Entity Identifier", True)
    days_to_look_back = siemplify.parameters.get("Days Back", None)

    similarCases = siemplify.get_similar_cases(consider_ports=consider_ports,
                                               consider_category_outcome=consider_category_outcome,
                                               consider_rule_generator=consider_rule_generator,
                                               consider_entity_identifiers=consider_entity_identifiers,
                                               days_to_look_back=days_to_look_back)
    if (len(similarCases) == 0):
        output_message = "No similar cases Found"
    else:
        similarCases.sort(key=int)
        output_message = "Found {0} similar cases: {1}".format(str(len(similarCases)), str(similarCases))
    
    siemplify.LOGGER.info(output_message)
    siemplify.end(output_message, str(similarCases))

if __name__ == '__main__':
    main()
