import argparse
import json
import os
import glob
import base64
#from tinify import tinify
from itertools import groupby

# Args
parser = argparse.ArgumentParser()
parser.add_argument("--marketplace-path", help="Email for new Username On Siemplify")
args = parser.parse_args()

# Consts
#args.marketplace_path = r'../../'
MARKETPLACE_PATH = args.marketplace_path
MARKETPLACE_INTEGRATIONS_PATH = os.path.join(MARKETPLACE_PATH, "Integrations")
MARKETPLACE_JSON_FILE_PATH = os.path.join(MARKETPLACE_PATH, "marketplace.json")
MARKETPLACE_CURRENT_VERSION_JSON_FILE_PATH = os.path.join(MARKETPLACE_PATH, "CurrentVersion.rn")
INTEGRATION_SUFFIX = ".def"
INTEGRATION_FULL_DETAILS_FILE_NAME = "{identifier}.fulldetails"
INTEGRATION_RELEASENOTES_FILENAME = "RN.json"
MINIMUM_SYSTEM_VERSION_ATTR = "MinimumSystemVersion"

IDENTIFIER_ATTR = "Identifier"
DISPLAY_NAME_ATTR = "DisplayName"
VERSION_ATTR = "Version"
DOCUMENTATION_LINK_ATTR = "DocumentationLink"
DESCRIPTION_ATTR = "Description"
INTEGRATION_PROPERTIES_ATTR = "IntegrationProperties"
NAME_ATTR = "Name"
FAMILY_ATTR = "Family"
ACTION_ID_ATTR = "actionIdentifier"
RELEASE_NOTES_VERSION_ATTR = "IntroducedInIntegrationVersion"
LATEST_RELEASE_TIME_ATTR = "LatestReleasePublishTimeUnixTime"
UPDATE_NOTIFICATION_EXPIRED_ATTR = "UpdateNotificationExpired"
NEW_NOTIFICATION_EXPIRED_ATTR = "NewNotificationExpired"

ACTIONS_DEF_DIR = "ActionsDefinitions"
JOBS_DEF_DIR = "Jobs"
CONNECTORS_DEF_DIR = "Connectors"
MANAGERS_DIR = "Managers"
MAPPING_RULES_DIR = "MappingRules"
WIDGETS_DIR = "Widgets"
CUSTOM_FAMILIES_DIR = "CustomFamilies"
EXAMPLE_USECASES_DIR = "ExampleCases"

INTEGRATION_SUPPORTED_ACTION_ATTR_NAME = "SupportedActions"
INTEGRATION_HAS_CONNECTORS = "HasConnectors"

TINIFY_API_KEY = "5QHf9mGNJjZBPDm5p43Q1G6MVblSg9WZ"

DAY_IN_MILISECONDS = 1000 * 60 * 60 * 24
UPDATE_NOTIFICATIONS_DAYS = 4
NEW_NOTIFICATION_DAYS = 30


class PackageDetails(object):
    def __init__(self):
        self.Identifier = None
        self.PackageName = None
        self.DisplayName = None
        self.Description = None
        self.DocumentationLink = None
        self.MinimumSystemVersion = None
        self.IntegrationProperties = []
        self.Actions = []
        self.Jobs = []
        self.Connectors = []
        self.Managers = []
        self.CustomFamilies = []
        self.ExampleUseCases = []
        self.MappingRules = []
        self.Widgets = []
        self.Version = None
        self.IsCustom = False
        self.ReleaseNotes = []


class IntegrationReleaseNote(object):
    def __init__(self, version, items, publish_time):
        self.Items = items
        self.Version = version
        self.PublishTimeUnixTime = publish_time * 1000 # convert to miliseconds


def get_marketplace_current_minimum_system_version():
    with open(MARKETPLACE_CURRENT_VERSION_JSON_FILE_PATH, 'r') as curversion_file:
        curversion = json.loads(curversion_file.read())
    return float(curversion[MINIMUM_SYSTEM_VERSION_ATTR])


def collect_sub_folders_names_from_integration_folder(integration_path, folder_name):
    folder_path = os.path.join(integration_path, folder_name)
    sub_folders = []
    if not os.path.exists(folder_path):
        return sub_folders
    for sub_folder in os.listdir(folder_path):
        sub_folder_path = os.path.join(folder_path, sub_folder)
        if os.path.isdir(sub_folder_path):
            sub_folders.append(sub_folder)
    return sub_folders


def collect_files_names_from_integration_folder(integration_path, folder_name):
    files_folder_path = os.path.join(integration_path, folder_name)
    files = []
    if not os.path.exists(files_folder_path):
        return files
    for action_file_name in os.listdir(files_folder_path):
        file_path = os.path.join(files_folder_path, action_file_name)
        if os.path.isfile(file_path):
            files.append(os.path.splitext(os.path.basename(file_path))[0])
    return files


def collect_objects_attribute_from_integration_folders(integration_path, folder_name, attribute):
    folder_path = os.path.join(integration_path, folder_name)
    attribute_values = []
    if not os.path.exists(folder_path):
        return attribute_values
    for file_name in os.listdir(folder_path):
        json_path = os.path.join(integration_path, folder_name, file_name)
        with open(json_path, 'r') as action_file:
            try:
                object_def = json.loads(action_file.read())
                attribute_values.append(object_def[attribute])
            except Exception as e:
                raise Exception("Error loading file def: {}".format(json_path))
    return attribute_values


def collect_integration_release_notes(integration_path):
    release_notes_path = os.path.join(integration_path, INTEGRATION_RELEASENOTES_FILENAME)
    release_notes = []
    if not os.path.exists(release_notes_path):
        return release_notes
    with open(release_notes_path, 'r') as rn_file:
        try:
            rn_def = json.loads(rn_file.read())

            group_by_version = groupby(rn_def, lambda x: x.get(RELEASE_NOTES_VERSION_ATTR))
            for version, items in group_by_version:
                items = list(items)
                max_publish_time = max([item.get("PublishTime", 0) for item in items])
                rn_object = IntegrationReleaseNote(version, [item["ChangeDescription"] for item in items], max_publish_time)
                release_notes.append(rn_object)

        except Exception as e:
            raise Exception("Error loading release notes def: {}, {}".format(release_notes_path, e))
    return release_notes


def calculate_latest_release_time(release_notes):
    if not len(release_notes):
        return 0
    latest_version = max([item.Version for item in release_notes])
    latest_version_rn = [item for item in release_notes if item.Version == latest_version][0]
    return latest_version_rn.PublishTimeUnixTime



# def compress_image(base64_image):
#     tinify.key = TINIFY_API_KEY
#     image_buffer = base64.b64decode(base64_image)
#     compressed = tinify.from_buffer(image_buffer).to_buffer()
#     return base64.b64encode(compressed).decode()

def main():
    integrations = []
    marketplace_minimum_system_version = get_marketplace_current_minimum_system_version()

    for integration_name in os.listdir(MARKETPLACE_INTEGRATIONS_PATH):
        print("Processing Integration: {}".format(integration_name))
        integration_path = os.path.join(MARKETPLACE_INTEGRATIONS_PATH, integration_name)
        integration_def_file_name_seacrh_results = glob.glob(os.path.join(integration_path, "*.def"))
        if integration_def_file_name_seacrh_results:
            integration_def_file_name = integration_def_file_name_seacrh_results[0]
        else:
            print("Cannot find def file for {}".format(integration_name))
            continue
        integration_def_path = os.path.join(integration_path, integration_def_file_name)
        with open(integration_def_path, 'r') as integration_file:
            try:
                integration_def = json.loads(integration_file.read())
            except Exception as e:
                raise Exception("Error loading integration def: {}".format(integration_def_path))

        # Collect objects from integration folder and pu then in .fulldetails file
        integration_pd = PackageDetails()
        integration_pd.Identifier = integration_def[IDENTIFIER_ATTR]
        integration_pd.PackageName = integration_def[DISPLAY_NAME_ATTR]
        integration_pd.DisplayName = integration_def[DISPLAY_NAME_ATTR]
        integration_pd.Description = integration_def[DESCRIPTION_ATTR]
        integration_pd.MinimumSystemVersion = integration_def[MINIMUM_SYSTEM_VERSION_ATTR]
        integration_pd.IntegrationProperties = integration_def.get(INTEGRATION_PROPERTIES_ATTR)
        integration_pd.DocumentationLink = integration_def.get(DOCUMENTATION_LINK_ATTR)
        integration_pd.Version = integration_def[VERSION_ATTR]
        integration_pd.Actions = collect_objects_attribute_from_integration_folders(integration_path, ACTIONS_DEF_DIR, NAME_ATTR)
        integration_pd.Jobs = collect_objects_attribute_from_integration_folders(integration_path, JOBS_DEF_DIR, NAME_ATTR)
        integration_pd.Connectors = collect_objects_attribute_from_integration_folders(integration_path, CONNECTORS_DEF_DIR, NAME_ATTR)
        integration_pd.Managers = collect_files_names_from_integration_folder(integration_path, MANAGERS_DIR)
        integration_pd.MappingRules = collect_files_names_from_integration_folder(integration_path, MAPPING_RULES_DIR)
        integration_pd.Widgets = collect_objects_attribute_from_integration_folders(integration_path, WIDGETS_DIR, ACTION_ID_ATTR)
        integration_pd.CustomFamilies = collect_objects_attribute_from_integration_folders(integration_path, CUSTOM_FAMILIES_DIR, FAMILY_ATTR)
        integration_pd.ExampleUseCases = collect_sub_folders_names_from_integration_folder(integration_path, EXAMPLE_USECASES_DIR)
        integration_pd.ReleaseNotes = collect_integration_release_notes(integration_path)

        integration_latest_release_time = calculate_latest_release_time(integration_pd.ReleaseNotes)
        if integration_latest_release_time > 0:
            integration_def[LATEST_RELEASE_TIME_ATTR] = integration_latest_release_time
            integration_def[UPDATE_NOTIFICATION_EXPIRED_ATTR] = (integration_latest_release_time + (UPDATE_NOTIFICATIONS_DAYS * DAY_IN_MILISECONDS))
            if integration_pd.Version == 1:
                integration_def[NEW_NOTIFICATION_EXPIRED_ATTR] = (integration_latest_release_time + (NEW_NOTIFICATION_DAYS * DAY_IN_MILISECONDS))


        # Write integration fulldetails json to integration folder
        details_json_name = INTEGRATION_FULL_DETAILS_FILE_NAME.format(identifier=integration_pd.Identifier)
        details_json_path = os.path.join(integration_path, details_json_name)
        with open(details_json_path, 'w') as dfile:
            dfile.write(json.dumps(integration_pd.__dict__, default=lambda o: o.__dict__, indent=4))

        
        integration_def[INTEGRATION_HAS_CONNECTORS] = len(integration_pd.Connectors)  > 0

        # Support legacy object
        integration_def[INTEGRATION_SUPPORTED_ACTION_ATTR_NAME] = []
        for action_file_name in os.listdir(os.path.join(integration_path, ACTIONS_DEF_DIR)):
            action_def_path = os.path.join(integration_path, ACTIONS_DEF_DIR, action_file_name)
            with open(action_def_path, 'r') as action_file:
                try:
                    actiondef = json.loads(action_file.read())
                except Exception as e:
                    raise Exception("Error loading action def: {}".format(action_def_path))

            integration_def[INTEGRATION_SUPPORTED_ACTION_ATTR_NAME].append({
                NAME_ATTR: actiondef[NAME_ATTR],
                DESCRIPTION_ATTR: actiondef[DESCRIPTION_ATTR]
            })

        #integration_def['ImageBase64'] = compress_image(integration_def['ImageBase64'])
        if 'SmallImageBase64' in integration_def:
            del integration_def['SmallImageBase64']
        integrations.append(integration_def)

    json_integration_list = json.dumps(integrations, sort_keys=True, indent=4, default=lambda o: o.__dict__)

    with open(MARKETPLACE_JSON_FILE_PATH, 'w') as result_file:
        result_file.write(json_integration_list)
        pass

    print("Done")


if __name__ == '__main__':
    main()
