from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction

ACTION_NAME = "Create\Updated Entity Properties"

BOOLEAN_VALUES = ['true', 'false']
ENTITY_ATTRS_MAP = {
    "isinternalasset": "is_internal",
    "isenriched": "is_enriched",
    "issuspicious": "is_suspicious",
    "isvulnerable": "is_vulnerable"
}


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    # Parameters.
    entity_field = siemplify.parameters.get('Entity Field')
    property_value = siemplify.parameters.get('Field Value', '')
    entities_to_update = []

    if entity_field.lower() == 'identifier':
        raise Exception("Cannot change the entities identifiers")

    # Fix pascal case field names
    if entity_field.lower() in ENTITY_ATTRS_MAP:
        entity_field = ENTITY_ATTRS_MAP[entity_field.lower()]

    for entity in siemplify.target_entities:
        if hasattr(entity, entity_field):
            if isinstance(getattr(entity, entity_field), bool):
                if property_value.lower() not in BOOLEAN_VALUES:
                    raise Exception('Variable is boolean, Wrong input, has to be True or False.')
                else:
                    setattr(entity, entity_field, property_value.lower() == 'true')
            else:
                setattr(entity, entity_field, property_value)
        else:
            entity.additional_properties[entity_field] = property_value

        entities_to_update.append(entity)

    if entities_to_update:
        siemplify.update_entities(entities_to_update)
        output_message = 'Property {0} were changed for the following entities: {1}'.format(
            entity_field,
            ','.join([unicode(entity.identifier).encode("utf8") for entity in siemplify.target_entities])
        )

    else:
        output_message = 'No target entities in scope.'

    siemplify.end(output_message, True)


if __name__ == "__main__":
    main()
