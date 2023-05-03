class BaseModel:
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class EndpointResult(BaseModel):
    def __init__(self, raw_data, hostname, local_ipv4, local_ipv6, external_ipv4, error, tables_data, limit):
        super(EndpointResult, self).__init__(raw_data)
        self.hostname = hostname
        self.local_ipv4 = local_ipv4
        self.local_ipv6 = local_ipv6
        self.external_ipv4 = external_ipv4
        self.error = error
        self.tables_data = tables_data
        self.limit = limit

    def to_json(self):
        if self.limit:
            query_results = self.raw_data.get("osQueryResult", [])

            for query_result in query_results:
                columns_number = len(query_result.get("columns", []))
                query_result["values"] = query_result.get("values")[:columns_number*self.limit] \
                    if query_result.get("values") else []

        return self.raw_data

    def to_tables(self):
        return [self.to_table(table_data) for table_data in self.tables_data]

    def to_table(self, table_data):
        columns_number = len(table_data.columns)
        rows = [table_data.values[i * columns_number:(i + 1) * columns_number]
                for i in range((len(table_data.values) + columns_number - 1) // columns_number)]

        return [dict(zip(table_data.columns, row)) for row in rows[:self.limit]]


class TableData:
    def __init__(self, columns, values):
        self.columns = columns
        self.values = values
