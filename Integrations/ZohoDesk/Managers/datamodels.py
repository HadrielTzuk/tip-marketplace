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


class Ticket(BaseModel):
    def __init__(self, raw_data, id, subject, description, ticket_number, status, created_time, resolution, email,
                 first_name, last_name):
        super(Ticket, self).__init__(raw_data)
        self.id = id
        self.subject = subject
        self.description = description
        self.ticket_number = ticket_number
        self.status = status
        self.created_time = created_time
        self.resolution = resolution
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

    def to_table(self):
        return {
            "Number": self.ticket_number,
            "Status": self.status,
            "Subject": self.subject,
            "Created Time": self.created_time,
            "Resolution": self.resolution,
            "Email": self.email,
            "Contact": f"{self.first_name or ''} {self.last_name or ''}"
        }

    def to_insight(self):
        return f'<p><strong>Title</strong>: {self.subject}</p>' \
               f'<p>{self.description}</p>'


class Comment(BaseModel):
    def __init__(self, raw_data, content, commented_time):
        super(Comment, self).__init__(raw_data)
        self.content = content
        self.commented_time = commented_time


class Department(BaseModel):
    def __init__(self, raw_data, id, name):
        super(Department, self).__init__(raw_data)
        self.id = id
        self.name = name


class Contact(BaseModel):
    def __init__(self, raw_data, id, email):
        super(Contact, self).__init__(raw_data)
        self.id = id
        self.email = email


class Product(BaseModel):
    def __init__(self, raw_data, id, name):
        super(Product, self).__init__(raw_data)
        self.id = id
        self.name = name


class Agent(BaseModel):
    def __init__(self, raw_data, id, name, email):
        super(Agent, self).__init__(raw_data)
        self.id = id
        self.name = name
        self.email = email


class Team(BaseModel):
    def __init__(self, raw_data, id, name):
        super(Team, self).__init__(raw_data)
        self.id = id
        self.name = name
