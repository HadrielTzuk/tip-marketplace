import os
import shutil
import dirtyjson
import json

# from FereraAct import FereraAct
CURRENT_VERSION_FOR_UPDATE = "1.0.10"
INTEGRATION_PATH = "../../../Integrations"
PACKAGE_PATH = "../../Packages/TIPCommon-{}".format(CURRENT_VERSION_FOR_UPDATE)
PACKAGE_NAME = "TIPCommon"
DEF_FILE_STRUCTURE = "{integ_path}/"
DEF_VERSION_KEY = "Version"
URLLIB_NAME = "urllib3-"
REQUESTS_NAME = "requests-"
IDNA_NAME = "idna-"
CHARDET_NAME = "chardet-"
CERTIFI_NAME = "certifi-"


# ferera = FereraAct()


def copy_package_contents(path):
    src_files = os.listdir(PACKAGE_PATH)
    for file_name in src_files:
        full_file_name = os.path.join(PACKAGE_PATH, file_name)
        if os.path.isfile(full_file_name):
            if "py3" in file_name and PACKAGE_NAME in file_name:
                continue

            shutil.copy(full_file_name, path)

    print ("Copied new package to {}".format(path.replace("../../../", "")))


def get_def_file_full_path(identifier):
    integ_full_path = os.path.join(INTEGRATION_PATH, identifier)
    def_file_name_list = [file for file in os.listdir(integ_full_path) if os.path.splitext(file)[1] == '.def']
    return "{}/{}".format(integ_full_path, def_file_name_list[0])


def read_def(identifier):
    def_file_full_path = get_def_file_full_path(identifier)
    with open(def_file_full_path, "r") as jsonFile:
        return dirtyjson.load(jsonFile)


def get_current_version(identifier):
    return float(read_def(identifier).get(DEF_VERSION_KEY, 0.0))


def get_db_file():
    return "{}.json".format(CURRENT_VERSION_FOR_UPDATE)


def get_updated_version(identifier):
    jsonFile = open(get_db_file(), "r")
    return dirtyjson.load(jsonFile).get(identifier, 0)


def should_update(identifier, current_version):
    if current_version == get_updated_version(identifier):
        print "Integrations {} already using TIPCommon {} version".format(identifier, CURRENT_VERSION_FOR_UPDATE)
        return False
    return True


def increment_integration_version(identifier, new_version):
    def_json = read_def(identifier)
    def_json[DEF_VERSION_KEY] = new_version
    with open(get_def_file_full_path(identifier), "w") as jsonFile:
        json.dump(def_json, jsonFile, indent=4, sort_keys=True)


def save_version_in_db(identifier, new_version):
    db_file = get_db_file()
    jsonFile = open(db_file, "r")
    data = json.load(jsonFile)
    jsonFile.close()
    if not data:
        data = {}

    data[identifier] = new_version
    jsonFile = open(db_file, "w+")
    jsonFile.write(json.dumps(data, jsonFile, indent=4, sort_keys=True))
    jsonFile.close()


def update_version(identifier, current_version):
    new_version = current_version + 1
    save_version_in_db(identifier, new_version)
    increment_integration_version(identifier, new_version)
    print "****** Integration {} updated from {} to {} to support TIP version {} ******".format(
        identifier, current_version, new_version, CURRENT_VERSION_FOR_UPDATE
    )


def update_old_versions(path, identifier):
    for fname in os.listdir(path):
        if PACKAGE_NAME in fname:
            current_version = get_current_version(identifier)
            if should_update(identifier, current_version):
                delete_file(path, fname)
                for filename in os.listdir(path):
                    if URLLIB_NAME in filename or REQUESTS_NAME in filename or IDNA_NAME in filename or CHARDET_NAME in filename or CERTIFI_NAME in filename:
                        delete_file(path, filename)
                copy_package_contents(path)
                # ferera.install_integration(identifier)
                update_version(identifier, current_version)


def delete_file(path, name):
    final_path = os.path.join(path, name)
    os.remove(final_path)
    print ("Removed {} file".format(final_path.replace("../../../", "")))


def create_db_if_not_exist():
    db_file = get_db_file()
    if not os.path.exists(db_file):
        with open(db_file, 'a') as f:
            json.dump({}, f)


create_db_if_not_exist()
for integ_path in os.listdir(INTEGRATION_PATH):
    cross_full_path = os.path.join(INTEGRATION_PATH, integ_path, "Dependencies", "cross")
    if os.path.isdir(cross_full_path):
        update_old_versions(cross_full_path, integ_path)
