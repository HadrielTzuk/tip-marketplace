from __future__ import annotations

import pathlib
from typing import Callable

import constants as consts
import enums
import paths
import script_utils
import widget_conf


def create_merged_file_by_type(
        config: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
        temp_dir: pathlib.Path,
        file_type: enums.WidgetFileTypes,
        temp_file_name: str,
        get_imports_func: Callable[[widget_conf.WidgetConf], str]
) -> pathlib.Path:
    """

    Args:
        config:
        action_widget_dir:
        temp_dir:
        file_type:
        temp_file_name:
        get_imports_func:

    Returns:

    """
    file_type_data = consts.FILE_TYPE_DATA_MAPPING[file_type]
    get_paths_fn = file_type_data['get_paths_func']

    path_list = get_paths_fn(
        configuration=config,
        action_widget_dir=action_widget_dir,
    )
    temp_file = temp_dir / f"{temp_file_name}{consts.TEMPLATE_FILE_EXTENSION}"

    content = ''
    for path in path_list:
        text = path.read_text()

        if file_type == enums.WidgetFileTypes.SCRIPT:
            text = script_utils.remove_dummy_js_fn_wrapper(text)

            if not text.startswith('    '):
                text = script_utils.indent_text(text)

        content = f'{content}\n{text}' if content else text.strip()

    import_content = get_imports_func(config)
    if import_content:
        import_content = script_utils.indent_text(import_content)
        content = f'{content.strip()}\n{import_content}'

    temp_file.write_text(content.strip())

    return temp_file


def create_template_files(
        config: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
        temp_dir: pathlib.Path,
        add_base_template_imports: bool | None = True,
) -> None:
    """

    Args:
        config:
        action_widget_dir:
        temp_dir:
        add_base_template_imports:
    """
    if add_base_template_imports:
        config.common_imports[consts.BASE_WIDGET_DIR_NAME] = \
            consts.IMPORT_ALL_JSON

    path_list = paths.get_all_template_paths_and_set_main_template(
        configuration=config,
        action_widget_dir=action_widget_dir
    )
    for path in path_list:
        temp_file = temp_dir / path.name
        temp_file.write_text(path.read_text())


def create_merged_script_file(
        config: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
        temp_dir: pathlib.Path,
) -> None:
    """

    Args:
        config:
        action_widget_dir:
        temp_dir:
    """
    create_merged_file_by_type(
        config=config,
        action_widget_dir=action_widget_dir,
        temp_dir=temp_dir,
        file_type=enums.WidgetFileTypes.SCRIPT,
        temp_file_name=consts.SCRIPT_TEMP_FILE_NAME,
        get_imports_func=paths.get_script_fn_import_content,
    )


def create_merged_style_file(
        config: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
        temp_dir: pathlib.Path,
) -> pathlib.Path:
    """

    Args:
        config:
        action_widget_dir:
        temp_dir:

    Returns:

    """
    create_merged_file_by_type(
        config=config,
        action_widget_dir=action_widget_dir,
        temp_dir=temp_dir,
        file_type=enums.WidgetFileTypes.STYLE,
        temp_file_name=consts.STYLE_TEMP_FILE_NAME,
        get_imports_func=paths.get_style_cls_import_content,
    )

    return temp_dir / consts.STYLE_TEMP_FILE_NAME


def create_flat_widget_file(
        content: str,
        action_widget_dir: pathlib.Path,
        prettify: bool | None = False,
) -> None:
    """

    Args:
        content:
        action_widget_dir:
        prettify:
    """
    widget_scripts_dir = action_widget_dir.parent.parent
    flat_html_file = (
            widget_scripts_dir /
            f"{action_widget_dir.stem}{consts.HTML_FILE_EXTENSION}"
    )

    if prettify:
        content = script_utils.prettify_content(content)

    flat_html_file.write_text(content)
