import pathlib
import re


_JS_FN_SIGNATURE_START_REGEXP = (
    # language=regexp
    '( *)?function\s*'
)

_JS_FN_SIGNATURE_END_REGEXP = (
    # language=regexp
    '\s*\((?:[^)(]+|\((?:[^)(]+|\([^)(]*\))*\))*\)\s*\{(?:[^}{]+|\{'
    '(?:[^}{]+|\{[^}{]*})*})*}'
)

# language=regexp
_CSS_CLS_SIGNATURE_END_REGEXP = '\s*\{(?:[^}{]+|\{(?:[^}{]+|\{[^}{]*})*})*}'


def function_from_js_file(fn_name: str, file_path: pathlib.Path) -> str:
    """
    Extract a function fn_name from a file file_path.

    Args:
        fn_name: The function's name to extract.
        file_path: The path object of the file where the function
            will be extracted from.

    Returns:
        The whole function (Signature + body) as a string
    """
    with file_path.open() as f:
        content = f.read()

    fn_regex = re.compile(
        f'{_JS_FN_SIGNATURE_START_REGEXP}{fn_name}{_JS_FN_SIGNATURE_END_REGEXP}'
    )
    match = fn_regex.search(content)
    fn_content = match.group()
    return (
        fn_content if match is not None
        else f'// Function {fn_name} was not found'
    )


def class_from_css_file(class_name: str, file_path: pathlib.Path) -> str:
    """
    Extract a CSS class class_name from a file file_path.

    Args:
        class_name: The class's name to extract.
        file_path: The path object of the file where the function
            will be extracted from

    Returns:
        The whole class (name + body) as a string
    """
    with file_path.open() as f:
        content = f.read()

    class_name = class_name.replace('.', r'\.')

    fn_regex = re.compile(
        f'{class_name}{_CSS_CLS_SIGNATURE_END_REGEXP}'
    )
    match = fn_regex.search(content)
    cls_content = match.group().strip()

    return (
        cls_content if match is not None
        else f'/*\nClass {class_name} was not found\n*/'
    )
