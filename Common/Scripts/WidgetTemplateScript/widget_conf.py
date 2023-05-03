from __future__ import annotations

import pathlib
from typing import Any, Dict, List, Union

import yaml

import constants as consts


ConfigTypeData = Dict[str, Union[bool, List[str]]]
CommonImports = Dict[str, ConfigTypeData]


def load_action_widget_import_conf(
        action_widget_dir: pathlib.Path
) -> dict[str, Any]:
    """
    Get the YAML data from the 'widget_imports_config.yaml' file.
    Args:
        action_widget_dir: The path of a specific action's widget in a
            WidgetElements folder.

    Returns:
        The YAML data as a dict.
    """
    config_file = action_widget_dir / consts.WIDGET_IMPORTS_CONFIG_FILE_NAME
    return yaml.safe_load(config_file.read_text())


def load_action_widget_data_conf(
        action_widget_dir: pathlib.Path
) -> dict[str, Any]:
    """
    Get the YAML data from the 'widget_data_config.yaml' file.
    Args:
        action_widget_dir: The path of a specific action's widget in a
            WidgetElements folder.

    Returns:
        The YAML data as a dict.
    """
    config_file = action_widget_dir / consts.WIDGET_DATA_CONFIG_FILE_NAME
    return yaml.safe_load(config_file.read_text())


class WidgetConf:
    """Widget Configuration Data Class"""

    def __init__(
            self,
            import_conf: dict[str, Any],
            data_conf: dict[str, Any]
    ) -> None:
        self.configuration = import_conf
        self.templates_data = data_conf
        self.main_template_str: str | None = (
            self.configuration.get(consts.MAIN_TEMPLATE_KEY)
        )
        self.main_template_path: pathlib.Path | None = None
        self.common_imports: CommonImports = (
            self.configuration.get(consts.COMMON_IMPORTS_KEY, {})
        )
        self.widget_imports: ConfigTypeData = (
            self.configuration.get(consts.WIDGET_IMPORTS_KEY, {})
        )
        self.integration_imports: ConfigTypeData = (
            self.configuration.get(consts.INTEGRATION_IMPORTS_KEY, {})
        )
        self.custom_imports: ConfigTypeData = (
            self.configuration.get(consts.CUSTOM_IMPORT_KEY, {})
        )
        self.import_fn: dict[str, dict[str, bool | list[str]]] = (
            self.configuration.get(consts.IMPORT_FN_KEY, {})
        )
        self.import_cls: dict[str, dict[str, bool | list[str]]] = (
            self.configuration.get(consts.IMPORT_STYLES_KEY, {})
        )
        self.import_logo_from_integration: bool = (
            self.templates_data.get(consts.IMPORT_INTEGRATION_SVG_KEY, False)
        )
