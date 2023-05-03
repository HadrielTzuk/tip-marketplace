from __future__ import annotations

import pathlib
from typing import Callable, List

import constants as consts
import enums
import extract
import main
import script_exceptions
import script_utils
import widget_conf


PathList = List[pathlib.Path]

SIEMPLIFY_MARKETPLACE_DIR_PATH = main.SCRIPT_BASEDIR_PATH.parent.parent.parent
COMMON_DIR_PATH = main.SCRIPT_BASEDIR_PATH.parent.parent
INTEGRATIONS_FOLDER_PATH = (
        SIEMPLIFY_MARKETPLACE_DIR_PATH / consts.INTEGRATIONS_DIR_NAME
)
WIDGET_COMMON_DIR = (
        COMMON_DIR_PATH /
        consts.SOURCE_CODE_DIR_NAME /
        consts.WIDGETS_DIR_NAME /
        consts.WIDGETS_COMMON_DIR_NAME
)


def validate_path_existence(path: pathlib.Path) -> None:
    """

    Args:
        path:
    """
    if not path.exists():
        if not path.suffix:  # Is a directory
            raise script_exceptions.DirectoryNotFoundError(
                f"The path '{path}' does not exists"
            )

        else:
            raise FileNotFoundError(
                f"The file '{path}' does not exists"
            )


def add_file_suffix_if_missing(file: str, suffix: str) -> str:
    """

    Args:
        file:
        suffix:

    Returns:

    """
    return file if file.endswith(suffix) else f"{file}{suffix}"


def add_common_import_paths_per_type(
        path_list: PathList,
        common_imports: widget_conf.CommonImports,
        file_type: enums.WidgetFileTypes,
) -> None:
    """

    Args:
        path_list:
        common_imports:
        file_type:
    """
    file_type_data = consts.FILE_TYPE_DATA_MAPPING[file_type]
    file_suffixes = file_type_data['suffixes']

    for widget_type, specifications in common_imports.items():
        widget_type_dir = WIDGET_COMMON_DIR / widget_type
        validate_path_existence(widget_type_dir)

        import_all = specifications.get(consts.IMPORT_ALL_KEY, False)
        if import_all:
            for path in widget_type_dir.iterdir():
                if path.is_file() and path.suffix in file_suffixes:
                    path_list.append(path)

        else:
            files = specifications.get(consts.FILES_KEY)
            if files is None:
                continue

            files = [
                file for file in files
                if script_utils.get_file_suffix(file) in file_suffixes
            ]

            _add_paths_to_path_list_per_type(
                path_list=path_list,
                files=files,
                files_dir=widget_type_dir
            )


def add_local_import_paths_per_type(
        path_list: PathList,
        files_dir: pathlib.Path,
        local_imports: dict[str, list[str]],
        file_type: enums.WidgetFileTypes,
) -> None:
    """

    Args:
        path_list:
        files_dir:
        local_imports:
        file_type:
    """
    file_type_data = consts.FILE_TYPE_DATA_MAPPING[file_type]
    import_all = local_imports.get(consts.IMPORT_ALL_KEY, False)
    file_suffixes = file_type_data['suffixes']

    if import_all:
        for path in files_dir.iterdir():
            if path.is_file() and path.suffix in file_suffixes:
                path_list.append(path)

    else:
        files = local_imports.get(consts.FILES_KEY)
        if files is None:
            return

        files = [
            file for file in files
            if script_utils.get_file_suffix(file) in file_suffixes
        ]

        _add_paths_to_path_list_per_type(
            path_list=path_list,
            files=files,
            files_dir=files_dir
        )


def add_custom_import_paths_per_type(
        path_list: PathList,
        custom_imports: dict[str, list[str]],
        file_type: enums.WidgetFileTypes,
) -> None:
    """

    Args:
        path_list:
        custom_imports:
        file_type:
    """
    if custom_imports is None:
        return

    file_type_data = consts.FILE_TYPE_DATA_MAPPING[file_type]
    file_suffixes = file_type_data['suffixes']

    for file in custom_imports:
        if script_utils.get_file_suffix(file) in file_suffixes:
            path = script_utils.get_specific_import_path(file)
            validate_path_existence(path)
            if path.is_file():
                path_list.append(path)


def _add_paths_to_path_list_per_type(
        path_list: PathList,
        files: list[str],
        files_dir: pathlib.Path,
) -> None:
    """

    Args:
        path_list:
        files:
        files_dir:
    """
    for file in files:
        file_path = files_dir / file
        validate_path_existence(file_path)
        if file_path.is_file():
            path_list.append(file_path)


def get_all_file_type_paths(
        configuration: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
        file_type: enums.WidgetFileTypes,
) -> PathList:
    """

    Args:
        configuration:
        action_widget_dir:
        file_type:

    Returns:

    """
    all_paths = []
    add_common_import_paths_per_type(
        path_list=all_paths,
        common_imports=configuration.common_imports,
        file_type=file_type
    )
    add_custom_import_paths_per_type(
        path_list=all_paths,
        custom_imports=configuration.custom_imports,
        file_type=file_type,
    )
    add_local_import_paths_per_type(
        path_list=all_paths,
        local_imports=configuration.widget_imports,
        file_type=file_type,
        files_dir=action_widget_dir,
    )
    add_local_import_paths_per_type(
        path_list=all_paths,
        local_imports=configuration.integration_imports,
        file_type=file_type,
        files_dir=action_widget_dir.parent,
    )

    return all_paths


def get_all_template_paths_and_set_main_template(
        configuration: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
) -> PathList:
    """

    Args:
        configuration:
        action_widget_dir:

    Returns:

    """
    all_templates = get_all_file_type_paths(
        configuration=configuration,
        action_widget_dir=action_widget_dir,
        file_type=enums.WidgetFileTypes.TEMPLATE,
    )
    set_main_template_path(
        configuration=configuration,
        templates_path_list=all_templates,
    )

    return all_templates


def get_all_script_paths(
        configuration: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
) -> PathList:
    """

    Args:
        configuration:
        action_widget_dir:

    Returns:

    """
    return get_all_file_type_paths(
        configuration=configuration,
        action_widget_dir=action_widget_dir,
        file_type=enums.WidgetFileTypes.SCRIPT,
    )


def get_all_style_paths(
        configuration: widget_conf.WidgetConf,
        action_widget_dir: pathlib.Path,
) -> PathList:
    """

    Args:
        configuration:
        action_widget_dir:

    Returns:

    """
    return get_all_file_type_paths(
        configuration=configuration,
        action_widget_dir=action_widget_dir,
        file_type=enums.WidgetFileTypes.STYLE,
    )


def set_main_template_path(
        configuration: widget_conf.WidgetConf,
        templates_path_list: PathList,
) -> None:
    """

    Args:
        configuration:
        templates_path_list:
    """
    main_template_name = configuration.main_template_str
    if main_template_name is None:
        raise script_exceptions.MissingMainTemplateKeyError(
            'The config yaml file is missing the '
            '"main_template" key or is empty'
        )

    if main_template_name == consts.BASE_TEMPLATE_FILE_NAME:
        return

    for path in templates_path_list:
        if path.name == main_template_name:
            configuration.main_template_path = path
            return

    raise FileNotFoundError(
        f"Could not find the main_template file {main_template_name!r}"
        "in any of the other template that were imported in the config file.\n"
        f"All templates {templates_path_list}"
    )


def get_all_import_content_by_type(
        imports: dict[str, dict[str, bool | list[str]]],
        extract_function: Callable[[str, pathlib.Path], str],
        data_key_for_type: str,
) -> str:
    """

    Args:
        imports:
        extract_function:
        data_key_for_type:

    Returns:

    """
    content = ''
    for file_name, data in imports.items():
        file_path = script_utils.get_specific_import_path(file_name)

        import_all = data.get(consts.IMPORT_ALL_KEY, False)
        if import_all:
            text = file_path.read_text()
            text = script_utils.remove_dummy_js_fn_wrapper(text)
            content = f'{content}\n{text}'

        else:
            things_to_import = data.get(data_key_for_type)
            for thing in things_to_import:
                imported_thing = extract_function(thing, file_path)
                content = f'{content}\n{imported_thing}'

    return content


def get_script_fn_import_content(configuration: widget_conf.WidgetConf) -> str:
    """

    Args:
        configuration:

    Returns:

    """
    return get_all_import_content_by_type(
        imports=configuration.import_fn,
        extract_function=extract.function_from_js_file,
        data_key_for_type=consts.FUNCTIONS_KEY,
    )


def get_style_cls_import_content(configuration: widget_conf.WidgetConf) -> str:
    """

    Args:
        configuration:

    Returns:

    """
    return get_all_import_content_by_type(
        imports=configuration.import_cls,
        extract_function=extract.class_from_css_file,
        data_key_for_type=consts.CLASSES_KEY,
    )


def get_body_script_content(temp_path: pathlib.Path) -> str:
    """

    Args:
        temp_path:

    Returns:

    """
    path = (
            temp_path /
            f'{consts.SCRIPT_TEMP_FILE_NAME}{consts.TEMPLATE_FILE_EXTENSION}'
    )
    return path.read_text()


def get_head_style_content(temp_path: pathlib.Path) -> str:
    """

    Args:
        temp_path:

    Returns:

    """
    path = (
            temp_path /
            f'{consts.STYLE_TEMP_FILE_NAME}{consts.TEMPLATE_FILE_EXTENSION}'
    )
    return path.read_text()
