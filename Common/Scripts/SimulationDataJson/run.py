import os
import re
import json

INTEGRATION_PATH = "../../../Integrations"
DEF_JSON_KEY_NAME = 'SimulationDataJson'
TYPES_KEYWORD = 'EntityTypes.'
TYPES_MAPPING = {
    "ALERT": "ALERT",
    "HOSTNAME": "HOSTNAME",
    "USER": "USERUNIQNAME",
    "ADDRESS": "ADDRESS",
    "MACADDRESS": "MacAddress",
    "PROCESS": "PROCESS",
    "FILENAME": "FILENAME",
    "FILEHASH": "FILEHASH",
    "URL": "DestinationURL",
    "THREATSIGNATURE": "THREATSIGNATURE",
    "EMAILMESSAGE": "EMAILSUBJECT",
    "USB": "USB",
    "EVENT": "EVENT",
    "CVEID": "CVEID",
    "DEPLOYMENT": "DEPLOYMENT",
    "CREDITCARD": "CREDITCARD",
    "PHONENUMBER": "PHONENUMBER",
    "CVE": "CVE",
    "THREATACTOR": "THREATACTOR",
    "THREATCAMPAIGN": "THREATCAMPAIGN",
    "GENERIC": "GENERICENTITY"
}


def read_def(path):
    with open(path, "r") as jsonFile:
        return json.load(jsonFile)


def update_def_files(entity_types, action_name, def_path):
    if os.path.isdir(def_path):
        for fname in os.listdir(def_path):
            if action_name in fname:
                def_file_full_path = os.path.join(def_path, fname)
                def_json = read_def(def_file_full_path)
                def_json[DEF_JSON_KEY_NAME] = json.dumps(entity_types)
                with open(def_file_full_path, "w") as jsonFile:
                    json.dump(def_json, jsonFile, indent=4, sort_keys=True)


def check_for_entities(path, def_path):
    for fname in os.listdir(path):
        action_script_path = os.path.join(path, fname)
        with open(action_script_path, "r") as action_script:
            body = action_script.read().split()
            # print(body)
            entity_types = set()
            for item in body:
                if TYPES_KEYWORD in item:
                    mapped_type = TYPES_MAPPING.get(re.sub('[^A-Za-z0-9]+', '', item.split(TYPES_KEYWORD)[1]))
                    entity_types.add(mapped_type)
            if entity_types:
                update_def_files({"Entities": list(entity_types)}, fname.split('.')[0], def_path)


for integ_path in os.listdir(INTEGRATION_PATH):
    actions_scripts_full_path = os.path.join(INTEGRATION_PATH, integ_path, "ActionsScripts")
    actions_def_full_path = os.path.join(INTEGRATION_PATH, integ_path, "ActionsDefinitions")
    if os.path.isdir(actions_scripts_full_path):
        check_for_entities(actions_scripts_full_path, actions_def_full_path)
