from datamodels import *


class ConnectWiseParser:
    def build_attachment_obj(self, raw_data):
        return Attachment(raw_data=raw_data, **raw_data)
