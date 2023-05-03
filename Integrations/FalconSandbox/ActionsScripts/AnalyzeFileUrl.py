from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from FalconSandboxManager import FalconSandboxManager
import sys
import base64
import json

SCRIPT_NAME = "Falcon Sandbox - AnalyzeFileUrl"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    configurations = siemplify.get_configuration('FalconSandbox')
    server_address = configurations['Api Root']
    key = configurations['Api Key']

    file_url= siemplify.parameters['File Url']
    env_id = siemplify.parameters['Environment']

    falcon_manager = FalconSandboxManager(server_address, key)
    siemplify.LOGGER.info("Connected to Falcon Sandbox")

    job_id, sha256 = falcon_manager.submit_file_by_url(file_url, env_id)
    max_threat_score = 0

    siemplify.LOGGER.info("Started job {} - {}".format(job_id, sha256))

    if falcon_manager.is_job_completed(job_id):
        siemplify.LOGGER.info("Job {} is completed.".format(job_id))

        reports = falcon_manager.get_scan_info(sha256, env_id)

        for index, report in enumerate(reports, 1):
            threat_score = report['threat_score']
            max_threat_score = max(threat_score, max_threat_score)

            siemplify.LOGGER.info("Threat Score: {}".format(threat_score))

            siemplify.LOGGER.info("Attaching JSON report")
            siemplify.result.add_json("Falcon Sandbox Report {} - {} - Environment {}".format(index, file_url, env_id),
                                      json.dumps(report))

        mist_report_name, misp_report = falcon_manager.get_report(job_id, type='misp')

        # Not working in server - throws 500
        # misp_json_report = falcon_manager.get_report(job_id, type='misp_json')

        siemplify.result.add_attachment(
            "Falcon Sandbox Misp Report",
            mist_report_name,
            base64.b64encode(misp_report)
        )


        # siemplify.result.add_attachment(
        #     "Falcon Sandbox Misp JSON Report",
        #     "misp_json_report.json",
        #     base64.b64encode(misp_json_report)
        # )

        siemplify.result.add_result_json(json.dumps(reports))
        siemplify.end(
            "Analysis completed - {}.\nMax Threat Score: {}".format(
                job_id, max_threat_score),
            json.dumps(max_threat_score), EXECUTION_STATE_COMPLETED)

    else:
        siemplify.end("Job {} in progress.".format(job_id),
                      json.dumps((job_id, sha256)),
                      EXECUTION_STATE_INPROGRESS)


def async_analysis():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("Start async")

    env_id = siemplify.parameters['Environment']

    try:
        configurations = siemplify.get_configuration('FalconSandbox')
        server_address = configurations['Api Root']
        key = configurations['Api Key']

        file_url = siemplify.parameters['File Url']

        job_id, sha256 = json.loads(siemplify.parameters["additional_data"])
        max_threat_score = 0

        falcon_manager = FalconSandboxManager(server_address, key)
        siemplify.LOGGER.info("Connected to Falcon Sandbox")

        if falcon_manager.is_job_completed(job_id):
            siemplify.LOGGER.info("Job {} is completed.".format(job_id))

            reports = falcon_manager.get_scan_info(sha256, env_id)

            for index, report in enumerate(reports, 1):
                threat_score = report['threat_score']
                max_threat_score = max(threat_score, max_threat_score)

                siemplify.LOGGER.info("Threat Score: {}".format(threat_score))

                siemplify.LOGGER.info("Attaching JSON report")
                siemplify.result.add_json("Falcon Sandbox Report {} - {} - Environment {}".format(index, file_url, env_id),
                                          json.dumps(report))

            mist_report_name, misp_report = falcon_manager.get_report(job_id, type='misp')

            # misp_json_report = falcon_manager.get_report(job_id,
            #                                              type='misp_json')

            siemplify.result.add_attachment(
                "Falcon Sandbox Misp Report",
                mist_report_name,
                base64.b64encode(misp_report)
            )
            # siemplify.result.add_attachment(
            #     "Falcon Sandbox Misp JSON Report",
            #     "misp_json_report.json",
            #     base64.b64encode(misp_json_report)
            # )

            siemplify.result.add_result_json(json.dumps(reports))
            siemplify.end(
                "Analysis completed - {}.\nMax Threat Score: {}".format(
                    job_id, max_threat_score),
                json.dumps(max_threat_score), EXECUTION_STATE_COMPLETED)


        else:
            siemplify.LOGGER.info("Job {} in progress.".format(job_id))
            siemplify.end("Job {} in progress.".format(job_id),
                          json.dumps((job_id, sha256)),
                          EXECUTION_STATE_INPROGRESS)

    except Exception as e:
        # Log the exception to file and raise it to client
        siemplify.LOGGER._log.exception(e)
        raise

if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_analysis()
