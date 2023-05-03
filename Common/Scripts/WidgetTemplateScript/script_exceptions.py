class WidgetTemplateScriptError(Exception):
    """Base error for all unique widget script errors"""


class DirectoryNotFoundError(WidgetTemplateScriptError):
    """The directory does not exist"""


class MissingMainTemplateKeyError(WidgetTemplateScriptError):
    """The config yaml file is missing the "main_template" key or is empty"""


class NotEnoughArgumentsError(WidgetTemplateScriptError):
    """Not enough arguments were provided to the script"""


class MissingSVGKeyInActionDefError(WidgetTemplateScriptError):
    """The key 'SVGImage' was not found in the integration's .def file"""
