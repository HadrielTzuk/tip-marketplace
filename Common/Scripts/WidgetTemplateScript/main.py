from __future__ import annotations

import argparse
import pathlib
import tempfile
import traceback

import argument_parser
import constants as consts
import file_creator
import paths
import script_logger
import script_utils
import templates_engine as t_engine
import widget_conf


SCRIPT_BASEDIR_PATH = pathlib.Path(__file__).parent


def widget_script_main() -> None:
    """Run the Widget Scripts"""

    logger = script_logger.Logger()
    logger.info('|-------------------  Main - Started  --------------------|')
    try:
        parser = argparse.ArgumentParser(prog='python3 main.py')
        args = argument_parser.get_parsed_arguments(parser)
        logger.info(f'Parsed script arguments: {vars(args)}')

        argument_parser.validate_args(args.all, args.integrations)

        for integration_folder in paths.INTEGRATIONS_FOLDER_PATH.iterdir():
            if script_utils.skip_integration_by_script_args(
                    all_arg=args.all,
                    integrations_arg=args.integrations,
                    ignore_integrations_arg=args.ignore_integrations,
                    current_integration=integration_folder.stem,
            ):
                continue

            integration = integration_folder.stem
            widgets_elements_dir = (
                    integration_folder /
                    consts.WIDGET_SCRIPTS_DIR_NAME /
                    consts.WIDGET_ELEMENTS_DIR_NAME
            )
            if not widgets_elements_dir.exists():
                continue

            logger.info(
                f'============ Starting {integration!r} main loop ============'
            )
            for action_widget_dir in widgets_elements_dir.iterdir():
                action_name = action_widget_dir.stem
                logger.info(
                    f'>>>>>>>>>>| Resolving {action_name!r} widget |<<<<<<<<<<'
                )
                import_config = widget_conf.load_action_widget_import_conf(
                    action_widget_dir
                )
                data_config = widget_conf.load_action_widget_data_conf(
                    action_widget_dir
                )
                widget_config = widget_conf.WidgetConf(
                    import_conf=import_config,
                    data_conf=data_config,
                )

                with tempfile.TemporaryDirectory() as temp_dir:
                    logger.info(f'Created temp file at {temp_dir}')
                    temp_path = pathlib.Path(temp_dir)

                    file_creator.create_template_files(
                        config=widget_config,
                        action_widget_dir=action_widget_dir,
                        temp_dir=temp_path
                    )
                    logger.info('Gathered all templates from the configuration')
                    file_creator.create_merged_script_file(
                        config=widget_config,
                        action_widget_dir=action_widget_dir,
                        temp_dir=temp_path
                    )
                    logger.info(
                        'Merged all script files from the configuration'
                    )
                    file_creator.create_merged_style_file(
                        config=widget_config,
                        action_widget_dir=action_widget_dir,
                        temp_dir=temp_path,
                    )
                    logger.info(
                        'Merged all style files from the configuration'
                    )

                    body_script = paths.get_body_script_content(temp_path)
                    head_style = paths.get_head_style_content(temp_path)
                    integration_def = script_utils.get_integration_def_file(
                        integration_folder
                    )
                    logo_content = script_utils.get_logo_from_integration_def(
                        integration_def_path=integration_def
                    ) if widget_config.import_logo_from_integration else None

                    flat_html_content = t_engine.get_resolved_template(
                        data=widget_config.templates_data,
                        main_template=widget_config.main_template_path,
                        templates_dir=temp_path,
                        base_template_body_script=body_script,
                        base_template_head_style=head_style,
                        integration_logo_content=logo_content,
                    )
                    logger.info('Resolved all templates')
                    logger.info('Deletes temp folder')

                file_creator.create_flat_widget_file(
                    content=flat_html_content,
                    action_widget_dir=action_widget_dir,
                    prettify=args.prettify,
                )
                flat_file = (
                        action_widget_dir.parent.parent /
                        action_widget_dir.stem
                )
                logger.info(
                    f'Created flat HTML file at '
                    f'{flat_file}{consts.HTML_FILE_EXTENSION}'
                )

                logger.info(
                    f'>>>>>>>>>>| Resolved {action_name!r} widget  |<<<<<<<<<<'
                )

            logger.info(
                f'============ Finished {integration!r} main loop ============'
            )

    except Exception as e:
        logger.error(f"An error occurred! Error: {e}")
        logger.error(f"{traceback.format_exc()}")

    logger.info('|-------------------- Main - Finished --------------------|')


if __name__ == '__main__':
    widget_script_main()
