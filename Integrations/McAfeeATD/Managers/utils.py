def get_entity(identifier, entities):
    for entity in entities:
        if entity.identifier.lower() == identifier.lower():
            return entity
