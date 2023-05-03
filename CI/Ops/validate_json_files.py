import argparse
import json
import os
import glob




# Args
parser = argparse.ArgumentParser()
parser.add_argument("--marketplace-path", help="Email for new Username On Siemplify")
args = parser.parse_args()

# Consts
MARKETPLACE_PATH = args.marketplace_path #"/opt/siemplify/siemplify_server/Marketplace/"
MARKETPLACE_INTEGRATIONS_PATH = os.path.join(MARKETPLACE_PATH, "Integrations")



def validate_json(integration_path):
        with open(integration_path, 'r') as action_file:
            try:
                json.loads(action_file.read())
            except Exception as e:
                raise Exception("Error loading file def: {}".format(integration_path))






def main():

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
        validate_json(integration_def_path)


    print("Done")


if __name__ == '__main__':
    main()
