from datamodels import *


class CylanceParser(object):

    def build_download_link_object(self, raw_data):
        return DownloadLink(
            raw_data=raw_data,
            url=raw_data.get(u"url", u"")
        )
