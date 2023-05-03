import argparse
import json
import os
import shutil
from datetime import datetime

import argument_parser
import create_doc_functions
import create_rn_functions
import creator_constants as consts
import creator_logger
import creator_utils as utils
import dateutil.parser
import docx
import style_obj_creator


def main() -> None:
    logger = creator_logger.Logger()
    try:
        logger.info('----------------- Main - Started -----------------')

        args = argument_parser.get_parsed_arguments(argparse.ArgumentParser())
        logger.info(f"Extracted script arguments: {args}")

        release_notes_folder_path = os.path.join(
            consts.MARKETPLACE_PATH,
            consts.RN_FOLDER_NAME
        )
        integrations_marketplace_path = os.path.join(
            consts.MARKETPLACE_PATH,
            consts.INTEGRATIONS_FOLDER_NAME
        )
        integration_versions_path = os.path.join(
            consts.MARKETPLACE_PATH,
            consts.INTEGRATION_VERSION_FILE_NAME
        )

        # Note that this file should be temporarily created by a pipeline
        # who runs this script. It shold copy the 'integration_versions.json'
        # file content from branch 'prod',
        # create the file 'prod_integration_versions.json' here,
        # and paste the production content inside.
        # This is done to keep a reference to the latest changes,
        # so the script could be run multiple times.
        # After the script is done the file should be deleted by the same pipeline.
        prod_integration_versions_path = os.path.join(
            consts.MARKETPLACE_PATH,
            consts.PROD_INTEGRATION_VERSION_FILE_NAME
        )

        minimum_version = (
            consts.MINIMUM_SOAR_VERSION
            if args.minimum_version in argument_parser.EMPTY_ARGUMENT
            else args.minimum_version
        )

        release_date = (
            datetime.today()
            if args.release_date in argument_parser.EMPTY_ARGUMENT
            else dateutil.parser.parse(args.release_date)
        )
        current_year = release_date.year  # 2022
        today_dd_mm_yy = release_date.strftime(consts.DD_MM_YY)  # 01/01/22
        today_dd_monthname_yyyy = release_date.strftime(
            consts.DD_MONTH_NAME_YYYY
        )  # 01 January, 2022
        logger.info(f"The release date is {today_dd_monthname_yyyy}")

        utils.validate_path_or_exception(integration_versions_path)
        utils.validate_path_or_exception(prod_integration_versions_path)
        integration_versions = utils.get_integration_versions(
            prod_integration_versions_path
        )

        release_notes = create_rn_functions.collect_release_notes_from_integrations(
            integration_versions,
            logger,
            release_date,
            integrations_marketplace_path
        )
        logger.info("Collected new release notes from integrations")

        html_rn_content = create_rn_functions.create_plain_html_rn(
            release_notes=release_notes,
            release_version=args.release_version,
            results_folder=os.path.join(
                release_notes_folder_path,
                consts.HTML_FOLDER_NAME
            ),
            formatted_current_date=today_dd_monthname_yyyy,
        )
        logger.info("created new release notes HTML content")

        header_style = style_obj_creator.create_header_style()
        title_style = style_obj_creator.create_title_style()
        publish_time_style = style_obj_creator.create_publish_time_style()
        tech_details_title_style = style_obj_creator.create_tech_details_title_style()
        tech_details_text_style = style_obj_creator.create_tech_details_text_style()
        main_text_style = style_obj_creator.create_main_text_title_style()
        footer_style = style_obj_creator.create_footer_style()
        logger.info("Created document style objects")

        document = docx.Document()
        result_path = os.path.join(
            release_notes_folder_path,
            consts.GOOGLEDOC_FOLDER_NAME
        )
        create_doc_functions.create_doc_rn(
            document=document,
            release_notes=release_notes,
            release_version=args.release_version,
            results_folder=result_path,
            minimum_version=minimum_version,
            integration_versions=integration_versions,
            current_year=current_year,
            formatted_current_date=today_dd_monthname_yyyy,
            header_style=header_style,
            title_style=title_style,
            publish_time_style=publish_time_style,
            tech_details_title_style=tech_details_title_style,
            tech_details_text_style=tech_details_text_style,
            main_text_style=main_text_style,
            footer_style=footer_style,
        )
        full_doc_path = os.path.join(
            result_path,
            f"{args.release_version}{consts.DOCX_EXTENSION}"
        )
        logger.info(f"Created the document at {full_doc_path}")

        utils.update_currentversion_file(
            html_content=html_rn_content,
            release_version=args.release_version,
            minimum_version=minimum_version,
            formatted_current_date=today_dd_mm_yy,
            marketplace_folder=consts.MARKETPLACE_PATH
        )
        logger.info("Updated the CurrentVersion.rn file")

        new_rn_file_name = f"{args.release_version}{consts.RN_EXTENSION}"
        shutil.copy(
            os.path.join(
                consts.MARKETPLACE_PATH,
                consts.CURRENT_VERSION_FILE_NAME
            ),
            os.path.join(
                consts.MARKETPLACE_PATH,
                consts.RN_FOLDER_NAME,
                new_rn_file_name
            )
        )
        logger.info(
            f"Copied the CurrentVersion.rn file to the ReleaseNotes directory as {new_rn_file_name}"
        )

        utils.write_integration_versions(
            integration_versions_path,
            integration_versions,
        )
        logger.info("Updated the integration_versions.json file")

    except dateutil.parser.ParserError as e:
        logger.error(f"{consts.UNSUPPORTED_DATE_FORMAT_ERR_MSG}. Error is: {e}")

    except json.JSONDecodeError as err:
        logger.error(
            f"A json could not be properly loaded or dumped. Error: {err}"
        )

    except Exception as error:
        logger.error(
            f"An error occurred while running the release notes creator script: {error}"
        )

    logger.info('----------------- Main - Finished -----------------')


if __name__ == "__main__":
    main()
