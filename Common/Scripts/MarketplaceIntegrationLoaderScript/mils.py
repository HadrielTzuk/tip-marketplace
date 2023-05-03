import argparse
import os
import sys

import utils
from logger import get_logger
from manager import MilsManager


def upload_integration(logger, integration):
    logger.info(f'---------- starting uploading integration {integration} ----------')
    manager = MilsManager(logger)
    logger.info(
        f"Successfully connected to Siemplify server {manager.api_root}"
    )

    zipped_integration = utils.zip_folder(
        utils.get_integration_path(integration),
        logger
    )
    logger.info(
        f"Successfully created integration zip file: {zipped_integration}"
    )
    # integration_id = utils.get_valid_integration_identifier(args.integration)
    integration_id = manager.get_integration_details(
        zipped_integration
    )["identifier"]

    logger.info(
        f"Successfully updated integration "
        f"{integration_id} metadata in Siemplify server"
    )
    res = manager.upload_integration_to_smp(
        zipped_integration, integration_id, False
    )
    logger.info(f"Response from Siemplify server: {repr(res)}")
    # verify
    assert integration_id in [details['identifier'] for details in manager.get_installed_integrations()]
    logger.info(
        f"Verified {integration_id} integration "
        f"successfully updated in Siemplify Instance"
    )
    logger.info(f'---------- finished uploading integration {integration} ----------')


def main(argsv):
    # TODO: add support for multiple integrations
    # TODO: add support for multiple machines

    logger = get_logger()
    parser = argparse.ArgumentParser(
        prog="mils",
        description='An interactive service which uploads integrations code '
                    'from the local "Integrations" repository, into Siemplify machine.',
        epilog='When uploading an integration code, use the integration identifier'
               'without any whitespaces. The integration identifier can be case-insensitive.'
    )
    parser.add_argument(
        '-i', '--integration',
        help='upload the integration code to Siemplify machine.'
             'multiple integrations can be uploaded at-once',
        nargs='*'
    )
    parser.add_argument(
        '-s', '--save-zip',
        action=argparse.BooleanOptionalAction,
        help='saves the created ZIP file to local file-storage'
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s version 1.0'
    )
    args = parser.parse_args(argsv)

    logger.info("############ Started MILS script execution ############")
    try:
        if args.integration:
            for integration in args.integration:
                upload_integration(logger, integration)

    except Exception as e:
        logger.critical(
            f"could not finish script execution: {e}", exc_info=True
        )

    finally:
        if args.save_zip is True:
            logger.info(f"Created zip files were saved to {os.path.abspath('tmp')}")
            logger.info(
                "Note - executing the script without the '-s' flag "
                "will delete all created zip files!"
            )
        else:
            logger.info("~~~ Clearing Cache ~~~")
            for f in os.listdir('tmp'):
                os.remove(os.path.join("tmp", f))
                logger.info(f'deleted {os.path.basename(f)} from {os.path.abspath("tmp")}')

        logger.info("############ Finished MILS script execution ############")


if __name__ == "__main__":
    main(sys.argv[1:])
