import enums


BASE_TEMPLATE_FILE_NAME = 'BaseTemplate.html'
WIDGET_IMPORTS_CONFIG_FILE_NAME = 'widget_imports_config.yaml'
WIDGET_DATA_CONFIG_FILE_NAME = 'widget_data_config.yaml'

SIEMPLIFY_MARKETPLACE_DIR_NAME = 'SiemplifyMarketPlace'
WIDGET_SCRIPTS_DIR_NAME = 'WidgetsScripts'
WIDGET_ELEMENTS_DIR_NAME = 'WidgetsElements'
INTEGRATIONS_DIR_NAME = 'Integrations'
SOURCE_CODE_DIR_NAME = 'SourceCode'
WIDGETS_DIR_NAME = 'Widgets'
WIDGETS_COMMON_DIR_NAME = 'WidgetsCommon'
BASE_WIDGET_DIR_NAME = 'BaseWidget'

COMMON_IMPORTS_KEY = 'common_imports'
WIDGET_IMPORTS_KEY = 'local_widget_imports'
INTEGRATION_IMPORTS_KEY = 'local_integration_imports'
CUSTOM_IMPORT_KEY = 'custom_imports'
TEMPLATE_DATA_KEY = 'template_data'
IMPORT_ALL_KEY = 'import_all'
MAIN_TEMPLATE_KEY = 'main_template_name'
FILES_KEY = 'files'
IMPORT_FN_KEY = 'script_functions'
IMPORT_STYLES_KEY = 'styles_classes'
FUNCTIONS_KEY = 'functions'
CLASSES_KEY = 'classes'
IMPORT_INTEGRATION_SVG_KEY = 'import_svg_from_integration'
IMPORTED_LOGO_CONTENT_KEY = 'imported_logo_content'

HTML_FILE_EXTENSION = '.html'
TEMPLATE_FILE_EXTENSION = HTML_FILE_EXTENSION
SCRIPT_FILE_EXTENSION = '.js'
STYLE_FILE_EXTENSION = '.css'

SCRIPT_TEMP_FILE_NAME = 'BaseTemplateScript'
STYLE_TEMP_FILE_NAME = 'BaseTemplateStyle'

IMPORT_ALL_JSON = {IMPORT_ALL_KEY: True}

DUMMY_JS_FN_WRAPPER_PRE = 'function _ignoreMe_() {\n'
DUMMY_JS_FN_WRAPPER_SUF = '}'

SVG_START_TAG = '<svg'
SVG_END_TAG = '</svg>'


import paths
FILE_TYPE_DATA_MAPPING = {
    enums.WidgetFileTypes.TEMPLATE: {
        'suffixes': [TEMPLATE_FILE_EXTENSION],
        'get_paths_func': paths.get_all_template_paths_and_set_main_template,
    },
    enums.WidgetFileTypes.SCRIPT: {
        'suffixes': [SCRIPT_FILE_EXTENSION],
        'get_paths_func': paths.get_all_script_paths,
    },
    enums.WidgetFileTypes.STYLE: {
        'suffixes': [STYLE_FILE_EXTENSION],
        'get_paths_func': paths.get_all_style_paths,
    },
}
