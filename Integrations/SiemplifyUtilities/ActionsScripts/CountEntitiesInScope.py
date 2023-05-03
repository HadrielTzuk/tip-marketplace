from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction


ACTION_NAME = 'Siemplify_Count Entities In Scope'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    # Parameters.
    entity_type = siemplify.parameters.get('Entity Type')

    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == entity_type]

    list_count = len(scope_entities)

    output_message = "There are {0} entities from {1} type.".format(list_count, entity_type)
    
    siemplify.end(output_message, list_count)


if __name__ == '__main__':
    main()
