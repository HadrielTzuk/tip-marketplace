from __future__ import annotations

import pathlib
from os import PathLike
from typing import Any

import jinja2

import constants as consts


def get_resolved_template(
        data: dict[str, Any] | None,
        main_template: pathlib.Path,
        templates_dir: str | PathLike,
        base_template_body_script: str,
        base_template_head_style: str,
        integration_logo_content: str | None = None,
) -> str:
    """
    Act

    Args:
        data:
        main_template:
        templates_dir:
        base_template_body_script:
        base_template_head_style:
        integration_logo_content:

    Returns:

    """
    if data is None:
        data = {}

    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(templates_dir),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = jinja_env.get_template(main_template.name)

    params = dict(
        base_template_body_script=base_template_body_script,
        base_template_head_style=base_template_head_style,
        **data
    )
    if integration_logo_content is not None:
        params[consts.IMPORTED_LOGO_CONTENT_KEY] = integration_logo_content

    return template.render(**params)
