from SiemplifyUtils import output_handler
import json
import logging as log
from requests import HTTPError
from SiemplifyAction import *


def GetIdentifiersAsString(target_entities):
    entitiesIdentifiers = []
    for entity in target_entities:
        entitiesIdentifiers.append(entity.identifier)
    return ", ".join(entitiesIdentifiers)


@output_handler
def main():
    siemplify = SiemplifyAction()

    message = siemplify.parameters["Message"]
    for entity in siemplify.target_entities:
        siemplify.add_entity_insight(entity, message)

    target_identifiers = GetIdentifiersAsString(siemplify.target_entities)

    if (siemplify.target_entities):
        output_message = "Added insight with message [%s] to [%s]" % (message, target_identifiers)
    else:
        output_message = "Scope is empty. Nothing happened."

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()