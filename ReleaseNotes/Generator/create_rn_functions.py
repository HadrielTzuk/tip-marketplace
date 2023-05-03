from __future__ import annotations

import json
import os
import time
from datetime import datetime

import creator_constants as consts
from bs4 import BeautifulSoup as bs
from creator_logger import Logger


def construct_html_rn(data: list | dict, parent: str, indent: int) -> str:
    """
    Construct html RN from data
    Args:
        data (list | dict):
        parent (str):
        indent (int): The amount of indent

    Returns:

    """
    html = ""
    if len(data):
        html += '<ul>'
        if isinstance(data, list):
            for item in data:
                # A Change

                symbol = ""
                if item.get("new"):
                    symbol = "NEW! "

                if item.get("deprecated"):
                    symbol = "DEPRECATED! "

                if item.get("removed"):
                    symbol = "REMOVED! "

                if item.get("regressive"):
                    symbol = "REGRESSIVE! "

                html += f'<li>{symbol}{item.get("description")}</li>'
        else:
            for k, v in data.items():
                if parent == "root":
                    # Integration
                    html += f'<li><b>{k}</b></li>'
                else:
                    # Item (action/job/connector)
                    html += f'<li>{k}</li>'
                html += construct_html_rn(v, k, indent + 1)
        html += '</ul>'
    return bs(html, features="lxml").prettify()


def collect_release_notes_from_integrations(
        integration_versions: dict[str, float],
        logger: Logger,
        release_time: datetime,
        marketplace_folder: str = consts.MARKETPLACE_PATH,
) -> dict[str, dict]:
    """
    Collects the RN data from the integrations
    Args:
        logger (Logger): A logger class to log data
        release_time: The release date
        integration_versions (dict[str, float]): The integrations' latest versions dict
        marketplace_folder (str): The path to the marketplace directory
        The default value is ..\..

    Returns:
        The release notes dict
    """
    release_notes = {
        "What's New": {},
        "What's Improved": {},
        "What's Regressed": {},
        "What's Removed": {},
        "What's Deprecated": {}
    }

    logger.info("Start comparing integration versions and collecting RN")
    for root, dirs, files in os.walk(marketplace_folder):
        for f in files:
            path = os.path.join(root, f)
            if f == consts.RN_FILE:
                integration_identifier = os.path.basename(os.path.dirname(path))

                with open(path, "r") as rn_file:
                    try:
                        integration_release_notes = json.loads(rn_file.read())

                    except json.JSONDecodeError as e:
                        raise ValueError(
                            f"Could not load the RN of the integration {integration_identifier}. "
                            f"Error: {e}"
                        )

                latest_integration_version = 0
                recently_updated = False
                for release_note in integration_release_notes:

                    if not integration_versions.get(integration_identifier):
                        logger.info(
                            f"Found new integration: {integration_identifier}"
                        )
                        integration_versions[integration_identifier] = 0

                    if release_note[
                        consts.RN_VERSION_KEY_NAME] > integration_versions.get(
                        integration_identifier
                    ):
                        logger.info(
                            f"Found new release notes in integration: {integration_identifier}"
                        )

                        recently_updated = True
                        if release_note[
                            consts.RN_VERSION_KEY_NAME] > latest_integration_version:
                            latest_integration_version = release_note[
                                consts.RN_VERSION_KEY_NAME]

                        if release_note["New"]:
                            release_note_category = release_notes["What's New"]

                        # elif release_note["Deprecated"] or :
                        #     release_note_category = release_notes["What's deprecated"]

                        # elif release_note["Regressive"]:
                        #     release_note_category = release_notes["What's regressed"]

                        # elif release_note["Removed"]:
                        #     release_note_category = release_notes["What's removed"]
                        else:
                            release_note_category = release_notes["What's Improved"]

                        if not release_note_category.get(integration_identifier):
                            release_note_category[integration_identifier] = {}

                        if not release_note_category[integration_identifier].get(release_note["ItemType"]):
                            release_note_category[integration_identifier][release_note["ItemType"]] = []

                        release_note_category[integration_identifier][release_note["ItemType"]].append(
                            {
                                "description": release_note["ChangeDescription"],
                                "ticket": release_note["TicketNumber"],
                                "new": release_note["New"],
                                "deprecated": release_note["Deprecated"],
                                "removed": release_note["Removed"],
                                "regressive": release_note["Regressive"]
                            }
                        )

                        release_note["PublishTime"] = int(
                            time.mktime(release_time.timetuple())
                        )

                if recently_updated:
                    with open(path, "w") as rn_file:
                        rn_file.write(
                            json.dumps(
                                integration_release_notes,
                                indent=4,
                                sort_keys=True
                            )
                        )

                if latest_integration_version > 0:
                    integration_versions[integration_identifier] = latest_integration_version

    return release_notes


def create_plain_html_rn(
        release_notes: dict,
        release_version: str,
        results_folder: str,
        formatted_current_date: str,
) -> str:
    """
    Create HTML RN file from release notes
    Args:
        release_notes (dict): The integration RN collected by collect_release_notes_from_integrations
        release_version (str): The version of the current release
        results_folder (str): The path to the folder of the results of the script
        formatted_current_date (str): A string representing the current date

    Returns:
        The generated HTML RN content
    """
    html_rn_content = ""

    if not os.path.exists(results_folder):
        os.makedirs(results_folder)

    with open(
            os.path.join(results_folder, f"{release_version}.html"),
            "w"
    ) as html_rn_target_file:
        html_rn_content += (
            f"<html><head></head><body><h2>Siemplify Marketplace Release Notes - "
            f"{release_version}</h2><h5>Published on {formatted_current_date}</h5>"
        )

        for category in release_notes.keys():
            if release_notes[category]:
                html_rn_content += f"<hr><h3>{category}</h3>"
                html_rn_content += construct_html_rn(
                    release_notes[category],
                    "root",
                    0
                )

        html_rn_content += "</body></html>"
        html_rn_target_file.write(html_rn_content)

    return html_rn_content
