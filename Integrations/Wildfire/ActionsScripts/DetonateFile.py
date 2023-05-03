from SiemplifyUtils import output_handler
from SiemplifyDataModel import InsightSeverity, InsightType
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv, add_prefix_to_dict
from WildfireManager import WildfireManager, WildfireManagerError
import base64
import time


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Wildfire')
    api_key = conf['Api Key']
    file_paths = siemplify.parameters.get('File Paths', '').split(",")

    # Connect to Wildfire
    wildfire_manager = WildfireManager(api_key)

    file_infos = {}

    # Upload file to Wildfire
    for file_path in file_paths:
        file_infos[file_path] = {
            'file_info': wildfire_manager.submit_file(file_path),
            'running': True
        }

    all_complete = False
    reports = {}

    # Get reports
    while not all_complete:
        # Set all_complete to True
        all_complete = True

        for file_path, file_info in file_infos.items():
            try:
                if file_info['running']:
                    # Not all completed - set it to False to enter while loop
                    # again
                    all_complete = False
                    time.sleep(5)
                    report = wildfire_manager.get_report(file_info['file_info']['md5'])

                    # Check if report is already available
                    if report and 'task_info' in report.keys() and report[
                        'task_info']:
                        # Report is ready
                        file_info['running'] = False
                        reports[file_path] = \
                            {
                                'file_info': report.get('file_info'),
                                'task_info': report.get('task_info')
                            }

            except WildfireManagerError:
                # Unable to get report - report is not ready yet
                all_complete = False

    for file_path, report in reports.items():
        # If entity is malware - mark entity as suspicious
        if report['file_info']['malware'] == 'yes':
            insight_msg = 'File {} was found malicious by WildFire'.format(file_path)
            siemplify.create_case_insight_internal(siemplify.case_id, None,
                                                   "Entity insight", insight_msg,
                                                   report['file_info']['md5'],
                                                   InsightSeverity.WARN,
                                                   InsightType.General)

        # Attach reports as csv
        flat_reports = dict_to_flat(report['task_info'])

        csv_output = flat_dict_to_csv(flat_reports)
        siemplify.result.add_entity_table(file_path,
                                          csv_output)

        # Download reports for file by its MD5 hash
        pdf_reports = wildfire_manager.get_pdf_report(report['file_info']['md5'])

        # Attach pdf to results
        siemplify.result.add_attachment(
            "Wildfire report {}".format(file_path),
            pdf_reports['filename'],
            base64.b64encode(pdf_reports['content'])
        )

    output_message = 'Uploaded {} and downloaded reports'.format(", ".join(file_paths))
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
