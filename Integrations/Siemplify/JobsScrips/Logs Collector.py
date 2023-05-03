from SiemplifyUtils import output_handler
from SiemplifyJob import SiemplifyJob
from PublisherAPIManager import PublisherAPIManager
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime
import sys
import json


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "Logs Collector"
    siemplify.LOGGER.info("----Logs Collector started---")
    publisher_id = siemplify.parameters.get("Publisher Id")
    verify_ssl = str(siemplify.parameters.get("Verify SSL")).lower() == str(True).lower()
    finished_successfully = False
    now_timestamp = unix_now()
    try:
        publisher_details = siemplify.get_publisher_by_id(publisher_id)
        publisher_api_root = publisher_details["server_api_root"]
        api_token = publisher_details["api_token"]
        publisher_api_manager = PublisherAPIManager(publisher_api_root, api_token, verify_ssl)
        unix_ms_last_run_time = siemplify.fetch_timestamp()
        # Get logs.
        siemplify.LOGGER.info("Fetching logs since {} ({})".format(unix_ms_last_run_time,
                                                                   convert_unixtime_to_datetime(unix_ms_last_run_time)))
        log_records = publisher_api_manager.fetch_log_records_since_timestamp(since=unix_ms_last_run_time)
        # Sort the records by updating time
        log_records = sorted(log_records, key=lambda record: record.get("updated", 0))
        siemplify.LOGGER.info("Found {} log records.".format(len(log_records)))
        if not log_records:
            siemplify.LOGGER.info("No log records were found.")
            finished_successfully = True

        else:
            try:
                siemplify.LOGGER.info("Saving records")
                siemplify.save_publisher_logs(log_records)
            except Exception as e:
                siemplify.LOGGER.error("Failed to save records")
                siemplify.LOGGER.exception(e)
            # In case we succeeded to save the records delete those records
            else:
                publisher_api_manager.delete_log_records_since_timestamp(since=unix_ms_last_run_time)

                siemplify.save_timestamp(new_timestamp=now_timestamp)
                siemplify.LOGGER.info(
                    "Saved last_run_time: {} ({})".format(now_timestamp, convert_unixtime_to_datetime(now_timestamp)))
                for log in log_records:
                    if log['level'] == 'ERROR':
                        siemplify.LOGGER.exception(json.dumps(log).encode("utf-8"))
                finished_successfully = True


    except Exception as e:
        siemplify.LOGGER.error("An error occurred while running Logs Collector")
        siemplify.LOGGER.exception(e)
        raise e
    finally:
        siemplify.LOGGER.info("----Logs Collector finished---")
    if siemplify.LOGGER.error_logged and not finished_successfully:
        raise Exception("Error was logged during execution, check the logs.s")


if __name__ == "__main__":
    main()