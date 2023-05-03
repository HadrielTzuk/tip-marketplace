import json
import pathlib
import textwrap

import bs4

import constants as consts
import paths
import script_exceptions


def remove_dummy_js_fn_wrapper(text: str) -> str:
    """

    Args:
        text:

    Returns:

    """
    if not text.startswith(consts.DUMMY_JS_FN_WRAPPER_PRE):
        return text

    return (
        text.removeprefix(consts.DUMMY_JS_FN_WRAPPER_PRE)
            .strip('\n')
            .removesuffix(consts.DUMMY_JS_FN_WRAPPER_SUF)
    )


def prettify_content(content: str) -> str:
    """

    Args:
        content:

    Returns:

    """
    soup = bs4.BeautifulSoup(content, features='lxml')
    formatter = bs4.formatter.HTMLFormatter(indent=2)
    return soup.prettify(formatter=formatter)


def get_widget_common_imports_path(wc_file_path: str) -> pathlib.Path:
    """

    Args:
        wc_file_path:

    Returns:

    """
    wc_file_path = wc_file_path.removeprefix(
        f'{consts.WIDGETS_COMMON_DIR_NAME}/'
    )

    file_path = paths.WIDGET_COMMON_DIR / wc_file_path
    paths.validate_path_existence(file_path)
    return file_path


def get_integrations_import_path(integrations_file_path: str) -> pathlib.Path:
    """

    Args:
        integrations_file_path:

    Returns:

    """
    integrations_file_path = integrations_file_path.removeprefix(
        f'{consts.INTEGRATIONS_DIR_NAME}/'
    )

    file_path = paths.INTEGRATIONS_FOLDER_PATH / integrations_file_path
    paths.validate_path_existence(file_path)
    return file_path


def get_marketplace_import_path(marketplace_file_path: str) -> pathlib.Path:
    """

    Args:
        marketplace_file_path:

    Returns:

    """
    if marketplace_file_path.startswith(consts.SIEMPLIFY_MARKETPLACE_DIR_NAME):
        marketplace_file_path = marketplace_file_path.removeprefix(
            f'{consts.SIEMPLIFY_MARKETPLACE_DIR_NAME}/'
        )

    file_path = paths.SIEMPLIFY_MARKETPLACE_DIR_PATH / marketplace_file_path
    paths.validate_path_existence(file_path)
    return file_path


def get_specific_import_path(import_file_path: str) -> pathlib.Path:
    """

    Args:
        import_file_path:

    Returns:

    """
    if import_file_path.startswith(consts.WIDGETS_COMMON_DIR_NAME):
        return get_widget_common_imports_path(import_file_path)

    if import_file_path.startswith(consts.INTEGRATIONS_DIR_NAME):
        return get_integrations_import_path(import_file_path)

    return get_marketplace_import_path(import_file_path)


def skip_integration_by_script_args(
        all_arg: bool,
        integrations_arg: list[str],
        ignore_integrations_arg: list[str],
        current_integration: str,
) -> bool:
    """

    Args:
        all_arg:
        integrations_arg:
        ignore_integrations_arg:
        current_integration:

    Returns:

    """
    return (
            (not all_arg and current_integration not in integrations_arg)
            or
            (ignore_integrations_arg and
             current_integration in ignore_integrations_arg)
    )


def indent_text(text: str, amount: int = 4, prefix_ch: str = ' ') -> str:
    """

    Args:
        text:
        amount:
        prefix_ch:

    Returns:

    """
    return textwrap.indent(text=text, prefix=amount * prefix_ch)


def get_file_suffix(file: str) -> str:
    """

    Args:
        file:

    Returns:

    """
    return f'.{file.split(".")[-1]}'


def get_logo_from_integration_def(integration_def_path: pathlib.Path) -> str:
    """

    Args:
        integration_def_path:

    Returns:

    """
    content = json.loads(integration_def_path.read_text())
    svg_logo = content.get('SVGImage') or content.get('SvgImage')

    if svg_logo is None:
        raise script_exceptions.MissingSVGKeyInActionDefError(
            f"The key 'SVGImage' wasn't found in {integration_def_path.name}"
        )
    
    svg_logo = prettify_content(svg_logo)
    svg_start_index = svg_logo.find(consts.SVG_START_TAG)
    svg_end_index = svg_logo.find(consts.SVG_END_TAG)
    svg_part = svg_logo[svg_start_index:svg_end_index + len(consts.SVG_END_TAG)]

    return svg_part


def get_integration_def_file(
        integration_folder: pathlib.Path
) -> pathlib.Path:
    """

    Args:
        integration_folder:

    Returns:

    """
    return integration_folder / f'Integration-{integration_folder.stem}.def'
