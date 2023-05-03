import json
import os

import creator_constants as consts
import simplejson


def validate_result_folder(results_folder: str) -> None:
    """
    Checks if a folder exists, if not, it creates it
    Args:
        results_folder (str): The path for the folder that will be validated
    """
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)


def validate_path_or_exception(path: str, ) -> None:
    """
    Checks if a path exists, if not, it raises a FileNotFoundError
    Args:
        path (str): The path to validate
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f'The file "{path}" was not found!')


def get_integration_versions(integration_versions_path: str) -> dict:
    """
    Get the integration_versions.json content
    Args:
        integration_versions_path (str): The path to the integration_versions.json file

    Returns:
        A loaded dict containing the integration_versions.json file content
    """
    with open(integration_versions_path, "r") as integration_versions_file:
        return json.loads(integration_versions_file.read())


def write_integration_versions(
        integration_versions_path: str,
        integration_versions: dict
) -> None:
    """
    Write new content into the integration_versions.json file
    Args:
        integration_versions_path (str): The path to the integration_versions.json file
        integration_versions (dict): The new integration versions dict content to write
    """
    with open(integration_versions_path, "w") as integration_versions_file:
        integration_versions_file.write(
            simplejson.dumps(
                simplejson.loads(json.dumps(integration_versions)),
                indent=4,
                sort_keys=True
            )
        )


def update_currentversion_file(
        html_content: str,
        release_version: str,
        minimum_version: str,
        formatted_current_date: str,
        marketplace_folder: str = consts.MARKETPLACE_PATH
) -> None:
    """
    Updates the CurrentVersion.rn file
    Args:
        html_content (str): The HTML content of the RN doc
        release_version (str): The current release version
        minimum_version (str): The minimum Siemplify version that can be used
        formatted_current_date (str): A string representing the current date
        marketplace_folder (str): The path to the marketplace directory
        The default value is ..\..
    """
    with open(
            os.path.join(marketplace_folder, consts.CURRENT_VERSION_FILE_NAME),
            "w"
    ) as main_rn:
        rn_content = json.dumps(
            {
                "Title": "Release Notes",
                "Description": "",
                "PublishedDate": formatted_current_date,
                "MinimumSystemVersion": minimum_version,
                "MarketplaceVersion": release_version,
                "Content": html_content
            }
        )
        main_rn.write(
            simplejson.dumps(
                simplejson.loads(rn_content),
                indent=4,
                sort_keys=True
            )
        )
