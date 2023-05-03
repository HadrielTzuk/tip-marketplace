from TIPCommon import extract_configuration_param, extract_action_param

from ExabeamAdvancedAnalyticsManager import ExabeamAdvancedAnalyticsManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    INTEGRATION_DISPLAY_NAME,
    REMOVE_ENTITY_FROM_WATCHLIST_SCRIPT_NAME,
    WATCHLIST_USERS_TYPE,
    WATCHLIST_ASSETS_TYPE,
    MAX_WATCHLIST_ITEMS
)
from exceptions import (
    ExabeamAdvancedAnalyticsNotFoundError,
    ExabeamAdvancedAnalyticsValidationError
)
from utils import get_users_watchlist_missing_items, get_assets_watchlist_missing_items

SUPPORTED_ENTITIES = [EntityTypes.USER, EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, REMOVE_ENTITY_FROM_WATCHLIST_SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root', is_mandatory=True,
                                           print_value=True)

    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token', is_mandatory=True,
                                            print_value=False)                                       

    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL', input_type=bool,
                                             is_mandatory=True, print_value=True)

    # Action configuration
    watchlist_title = extract_action_param(siemplify, param_name='Watchlist Title', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    suitable_entities = []
    successful_entities_identifiers = []
    failed_entities_identifiers = []

    try:
        manager = ExabeamAdvancedAnalyticsManager(api_root=api_root, api_token=api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        siemplify.LOGGER.info(f"Searching for watchlist title {watchlist_title}")
        found_watchlist = next(iter(filter(lambda watchlist: watchlist.title == watchlist_title, manager.list_watchlists())), None)

        if not found_watchlist:
            raise ExabeamAdvancedAnalyticsNotFoundError(f"Watchlist {watchlist_title} was not found in {INTEGRATION_DISPLAY_NAME}")

        if found_watchlist.category not in [WATCHLIST_USERS_TYPE, WATCHLIST_ASSETS_TYPE]:
            raise ExabeamAdvancedAnalyticsValidationError(
                f"Watchlists with category 'AssetLabels' and 'UserLabels' are not supported in this action.")

        siemplify.LOGGER.info(f"Successfully found watchlist {found_watchlist.title} of category {found_watchlist.category}")

        for entity in siemplify.target_entities:

            if entity.entity_type not in SUPPORTED_ENTITIES:
                siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                continue

            # Username entities can only be added to wathclists with category 'Users'
            if entity.entity_type == EntityTypes.USER and found_watchlist.category != WATCHLIST_USERS_TYPE:
                failed_entities_identifiers.append(entity.identifier)
                siemplify.LOGGER.info(
                    f"Entity {entity.identifier} is ignored because entity type does not match watchlist category")
                continue

            # IP/Hostnames entities can only be added to watchlists of category 'Assets'
            if (entity.entity_type == EntityTypes.ADDRESS or entity.entity_type == EntityTypes.HOSTNAME) \
                    and found_watchlist.category != WATCHLIST_ASSETS_TYPE:
                failed_entities_identifiers.append(entity.identifier)
                siemplify.LOGGER.info(
                    f"Entity {entity.identifier} is ignored because entity type does not match watchlist category")
                continue

            suitable_entities.append(entity)

        if suitable_entities:
            suitable_entities_identifiers = [entity.identifier for entity in suitable_entities]
            try:
                siemplify.LOGGER.info(
                    "Removing from watchlist {} entities:\n   {}".format(watchlist_title, "\n   ".join(suitable_entities_identifiers)))
                num_added_entities = manager.remove_entities_from_watchlist(
                    watchlist_id=found_watchlist.watchlist_id,
                    watchlist_category=found_watchlist.category,
                    entities=suitable_entities_identifiers
                )
                siemplify.LOGGER.info(f"Successfully removed {num_added_entities} entities")

                if num_added_entities != len(suitable_entities_identifiers):
                    siemplify.LOGGER.info(f"Checking which entities failed be removed from watchlist")
                    watchlist = manager.get_watchlist(
                        watchlist_type=found_watchlist.category,
                        watchlist_id=found_watchlist.watchlist_id,
                        items_limit=MAX_WATCHLIST_ITEMS
                    )
                    # Search for existing entities that were successfully removed
                    successful_entities_identifiers.extend(get_users_watchlist_missing_items(suitable_entities_identifiers, watchlist)
                                                           if found_watchlist.category == WATCHLIST_USERS_TYPE else
                                                           get_assets_watchlist_missing_items(suitable_entities_identifiers, watchlist))

                    if successful_entities_identifiers:
                        siemplify.LOGGER.info(
                            "Entities that were successfully removed:\n   {}".format("\n   ".join(successful_entities_identifiers)))
                    else:
                        siemplify.LOGGER.info(f"No entities were successfully removed from watchlist")

                    failed_entities_identifiers.extend([entity.identifier for entity in suitable_entities if entity.identifier not in
                                                        successful_entities_identifiers])
                else:
                    successful_entities_identifiers.extend(suitable_entities_identifiers)

            except Exception as error:
                siemplify.LOGGER.error("An error occurred on entities {}".format("\n   ".format(suitable_entities_identifiers)))
                siemplify.LOGGER.exception(error)

        if successful_entities_identifiers:
            output_message += "Successfully removed the following entities from the watchlist {} in {}:\n   {}\n\n".format(
                watchlist_title, INTEGRATION_DISPLAY_NAME, "\n   ".join(successful_entities_identifiers)
            )
            result_value = True
        else:
            output_message += f"No entities were removed from the watchlist {watchlist_title} in {INTEGRATION_DISPLAY_NAME}."

        if failed_entities_identifiers and successful_entities_identifiers:
            output_message += "Action wasn't able to remove the following entities from watchlist {} in {}:\n   {}\n\n".format(
                watchlist_title, INTEGRATION_DISPLAY_NAME, "\n   ".join(failed_entities_identifiers)
            )

    except Exception as error:
        output_message = f"Error executing action \"{REMOVE_ENTITY_FROM_WATCHLIST_SCRIPT_NAME}\". Reason: {error}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
