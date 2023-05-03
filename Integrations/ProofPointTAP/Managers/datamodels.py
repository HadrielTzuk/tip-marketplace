from TIPCommon import dict_to_flat, add_prefix_to_dict


class BaseModel:
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_table(self):
        return dict_to_flat(self.to_json())

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.raw_data)
        return add_prefix_to_dict(data, prefix) if prefix else data


class Campaign(BaseModel):
    def __init__(self, raw_data, id=None, name=None, description=None, startDate=None, families=None, malware=None,
                 techniques=None, brands=None, **kwargs):
        super().__init__(raw_data)
        self.id = id
        self.name = name
        self.description = description
        self.start_date = startDate
        self.families = families
        self.malwares = malware
        self.techniques = techniques
        self.brands = brands

    def to_table(self):
        return {
            "Name": self.name,
            "Description": self.description,
            "Start Date": self.start_date,
            "Related Families": ', '.join([fam.get('name', '') for fam in self.families]) if self.families else "",
            "Related Malware": ', '.join([m.get('name', '') for m in self.malwares]) if self.malwares else "",
            "Related Techniques": ', '.join([t.get('name', '') for t in self.techniques]) if self.techniques else "",
            "Related Actors": ', '.join([brand.get('name', '') for brand in self.brands]) if self.brands else "",
        }

    def to_insight(self):
        html_content = ""

        html_content += f"<h2><strong>{self.name}</strong></h2>"
        html_content += f"<p><strong>Start Date: {self.start_date}</strong><br />"
        html_content += f"<p><strong>Related Families: " \
                        f"{', '.join([fam.get('name', '') for fam in self.families]) if self.families else 'N/A'}" \
                        "</strong><br />"
        html_content += f"<strong>Related Malware: " \
                        f"{', '.join([m.get('name', '') for m in self.malwares]) if self.malwares else 'N/A'}" \
                        "</strong><br />"
        html_content += f"<strong>Related Techniques: " \
                        f"{', '.join([t.get('name', '') for t in self.techniques]) if self.techniques else 'N/A'}" \
                        "</strong><br />"
        html_content += f"<strong>Related Actors: " \
                        f"{', '.join([brand.get('name', '') for brand in self.brands]) if self.brands else 'N/A'}" \
                        "</strong><br /></p>"
        description = self.description.replace('\r\n', '<br>').replace('\n', '<br>')
        html_content += f"<p><strong>{description}</strong></p>"

        return html_content


class ForensicObj(BaseModel):
    def __init__(self, raw_data, forensics):
        super().__init__(raw_data)
        self.forensics = forensics


class Forensic(BaseModel):
    def __init__(self, raw_data, type=None, display=None, malicious=None, what=None, platforms=None, **kwargs):
        super().__init__(raw_data)
        self.type = type
        self.display = display
        self.malicious = malicious
        self.what = what
        self.platforms = platforms

    def to_table(self):
        return {
            "Type": self.type,
            "Description": self.display,
            "Malicious": self.malicious,
            "URL": self.what.get('url', ''),
            "Path": self.what.get('path', ''),
            "SHA256": self.what.get('sha256', ''),
            "IP Address": self.what.get('ip', ''),
            "Platforms": ", ".join([p.get('name', '') for p in self.platforms]) if self.platforms else ""
        }


class DecodedURL(BaseModel):
    def __init__(self, raw_data, encodedUrl=None, decodedUrl=None, error=None, success=None, **kwargs):
        super().__init__(raw_data)
        self.encoded_url = encodedUrl
        self.decoded_url = decodedUrl
        self.error = error
        self.success = success
