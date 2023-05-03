from SiemplifyUtils import output_handler
# ==============================================================================
# title           :UpdateComments.py
# description     :Siemplify job for updating comments in CaseWall and in ConnectWize
# author          :org@siemplify.co
# date            :01-07-17
# python_version  :3.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from ArcsightManager import ArcsightManager
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import *
import urllib3
import requests

# =====================================
#             CONSTANTS               #
# =====================================
CLOSE_CASE_XML = """<?xml version=""1.0"" encoding=""UTF-8""?> 
<!DOCTYPE archive SYSTEM ""../../schema/xml/archive/arcsight-archive.dtd""> 
<archive buildVersion=""{0}"" buildTime=""{1}"" createTime=""{2}""> 
   <ArchiveCreationParameters> 
      <include> 
         <list> 
            <ref type=""Case"" uri=""{3}"" id=""{4}""/> 
         </list> 
      </include> 
   </ArchiveCreationParameters>    
    {5}
</archive>
"""
CLOSED_CASES_PATH = r"I:\UpdatedCases"
CASES_CLOSE_STATUS_ENUM = '2'
ARCSIGHT_PRODUCT = "Arcsight" # Should be changed according to connector


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.LOGGER.info("-----Job Started-----")
        server_address = siemplify.parameters['Server Address']
        username = siemplify.parameters['Username']
        password = siemplify.parameters['Password']
        arcsight_manager = ArcsightManager(server_address, username, password)
        last_timestamp = siemplify.fetch_and_save_timestamp(datetime_format=True, timezone="UTC")

        siemplify.LOGGER.info("Getting closed Archsight cases from Siemplify")

        closed_cases = []
        closed_cases_alerts = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(
            last_timestamp, None)

        # Fetch closed Arcsight cases from Siemplify to close them in Arcsight
        for alert_ticket_id in closed_cases_alerts:
            case_list = siemplify.get_cases_by_ticket_id(alert_ticket_id)
            for case in case_list:
                if case['product'] == ARCSIGHT_PRODUCT:
                    closed_cases.append(case)


        siemplify.LOGGER.debug("Fetched {0} closed cases".format(len(closed_cases)))

        for case in closed_cases:
            # Close case in arcsight
            build_version = case['version']
            build_time = case['build_time']
            creation_time = ['create_time']
            case_xml = case['xml']
            # parse xml
            case_name = case_xml.Attribute('name')
            ticket_id = case_xml.Attribute('id')
            case_uri = case_xml.Element("childOf").Element("list").Elements("ref").First().Attribute("uri").Value
            # Set stage : closed
            # Set actionsTaken : comment

            # construct xml to write to file in path




        siemplify.LOGGER.info("Finish closing Archsight cases.")

        siemplify.LOGGER.info("-----Job Finished-----")

    except Exception as e:
        siemplify.LOGGER.exception('Got exception on main handler')
        raise


if __name__ == '__main__':
    main()
