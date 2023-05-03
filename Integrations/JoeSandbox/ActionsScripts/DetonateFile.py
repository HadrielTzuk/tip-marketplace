from SiemplifyUtils import output_handler
from JoeSandboxManager import JoeSandboxManager, REPORT_WEB_LINK, JoeSandboxLimitManagerError
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
import sys
import base64
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'JoeSandbox - Detonate file'

    conf = siemplify.get_configuration('JoeSandbox')
    api_key = conf['Api Key']
    use_ssl = conf['Use SSL'].lower() == 'true'
    joe = JoeSandboxManager(api_key, use_ssl)

    file_paths = siemplify.parameters.get('File Paths', '').split(',') if siemplify.parameters.get('File Paths') else []

    # value returned by get
    comments = siemplify.parameters.get('Comment', "Uploaded by Siemplify")
    siemplify.LOGGER.info("Start Detonate File Action.")

    # TODO: Check Linux
    web_ids = []

    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as sample:
                web_ids.append((joe.analyze(sample, comments=comments), file_path))
        except JoeSandboxLimitManagerError as e:
            # Reached max allowed API requests - notify user
            siemplify.LOGGER.error('The number of allowed submissions (20) per day have been reached. {0}'.format(e))
            siemplify.end('The number of allowed submissions (20) per day have been reached.', 'false',
                          EXECUTION_STATE_FAILED)
        except Exception as e:
            siemplify.LOGGER.error("Unable to submit {}. Error: {}".format(file_path, str(e)))
            siemplify.LOGGER.exception(e)

    if not web_ids:
        siemplify.end(
            'No files were submitted. Check logs for details.',
            'false',
            EXECUTION_STATE_FAILED)

    output_massage = "Successfully submitted files: {}.".format(", ".join([file_path for _, file_path in web_ids]))
    siemplify.LOGGER.info(output_massage)

    siemplify.end(output_massage, json.dumps(web_ids), EXECUTION_STATE_INPROGRESS)


def fetch_scan_report_async():

    siemplify = SiemplifyAction()
    siemplify.script_name = 'JoeSandbox - Detonate file'
    try:
        conf = siemplify.get_configuration('JoeSandbox')
        api_key = conf['Api Key']
        use_ssl = conf['Use SSL'].lower() == 'true'
        joe = JoeSandboxManager(api_key, use_ssl)

        download_resource = siemplify.parameters.get('Report Format', 'html')
        # Extract web_ids
        web_ids = json.loads(siemplify.parameters["additional_data"])

        is_completed = True
        json_results = {}

        for web_id, file_path in web_ids:
            try:
                joe.get_analysis_info(web_id)
                if not joe.is_analysis_completed(web_id):
                    is_completed = False

            except Exception as e:
                siemplify.LOGGER.error("Unable to get analysis of file {}. Waiting.".format(file_path))
                siemplify.LOGGER.exception(e)

        if is_completed:
            detected_files = []

            for web_id, file_path in web_ids:
                try:
                    analysis_info = joe.get_analysis_info(web_id)
                    siemplify.LOGGER.info("Fetching report for {}.".format(file_path))

                    json_results[file_path] = analysis_info
                    # Download analysis
                    full_report = joe.download_report(web_id, download_resource)
                    try:
                        siemplify.result.add_attachment('{0} Report'.format(file_path), 'JoeSandboxReport.{0}'.format(download_resource), base64.b64encode(full_report))
                    except Exception as e:
                        # Attachment cannot be larger than 3 MB
                        siemplify.LOGGER.error(
                            "Can not add attachment: {}.\n{}.".format(file_path,
                                                                      str(e)))

                    siemplify.result.add_link('JoeSandbox Report - Web Link', REPORT_WEB_LINK.format(analysis_info.get('analysisid')))

                    # Check for detection risk - result 'suspicious'
                    if joe.is_detection_suspicious(analysis_info):
                        detected_files.append(file_path)
                        try:
                            siemplify.create_case_insight(title="Case Insight", content='Found as suspicious by JoeSandbox.', triggered_by='JoeSandbox', entity_identifier=file_path, insight_type=0, severity=1)
                        except Exception as e:
                            siemplify.LOGGER.error("Can not add insight. Error: {0}".format(e))

                except Exception as e:
                    siemplify.LOGGER.error(
                        "Can get report of file {}. Skipping. Error: {}".format(file_path, str(e)))
                    siemplify.LOGGER.exception(e)

            if detected_files:
                output_massage = "{0} files were detected as suspicious by Joe Sandbox.".format(
                    len(detected_files))

            else:
                output_massage = "Completed analysis of {} files. No files were detected as suspicious by Joe Sandbox.".format(
                    len(web_ids))

            # add json
            siemplify.result.add_result_json(json_results)
            siemplify.end(output_massage, 'true', EXECUTION_STATE_COMPLETED)

        else:
            siemplify.LOGGER.info("Files are still queued for analysis.")
            output_massage = "Continuing...the requested items are still queued for analysis"
            siemplify.end(output_massage, json.dumps(web_ids), EXECUTION_STATE_INPROGRESS)

    except Exception as e:
        siemplify.LOGGER.exception(e)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        fetch_scan_report_async()
