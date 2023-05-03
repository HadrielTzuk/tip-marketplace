import os
import json
dir = r'D:\SiemplifyMarketplace\Integrations'
DEF_JSON_KEY_NAME = "MarketingDisplayName"
INTEGRATION_DEF_SUFFIX = ".def"


def read_def(path):
    with open(path, "r") as jsonFile:
        return json.load(jsonFile)


def update_def_file(path):
    def_json = read_def(path)
    def_json[DEF_JSON_KEY_NAME] = ""
    with open(path, "w") as jsonFile:
        json.dump(def_json, jsonFile, indent=4)


for subpath in os.listdir(dir):
    integration_path = os.path.join(dir, subpath)
    if os.path.isdir(integration_path):
        integration_path = os.path.join(dir, subpath)
        for file in os.listdir(integration_path):
            if file.endswith(INTEGRATION_DEF_SUFFIX):
                update_def_file(os.path.join(integration_path,file))
                print ("file {} was updated".format(file))


"""
1. read the def file
2. create a list with all of the display names that suppose to be equal to the marketing name (all of the empty values under marketing name in the excel)
3. check if the display name in the def exists in your list --> if yes, copy the value to the 'marketing' :key
4. if no, skip
"""