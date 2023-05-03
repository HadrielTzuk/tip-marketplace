import datetime
import os
import pandas as pandas
from utils import get_value_for_search
from exceptions import CSVManagerException, CSVEncodingException
from datamodels import CSVItem

# CONSTANTS
CSV_EXTENSION = ".csv"
ENRICHMENT_PREFIX = "CSVEnrichment"
FILE_ENCODINGS_DEFAULT = ["utf-8", "latin-1", "iso-8859-1"]


class CSVManager(object):
    def __init__(self, siemplify):
        self.siemplify = siemplify

    @staticmethod
    def is_csv_file_pass_time_filter(file_path, days_back=None):
        """
        Check if file is CSV file and if stands in time restriction
        :param file_path: {str} file path
        :param days_back: {str} how many days back to look for
        :return: {str} is file valid
        """
        pass_time_filter = True
        if days_back:
            start_from_date = datetime.datetime.now() - datetime.timedelta(days=int(days_back))
            pass_time_filter = datetime.datetime.fromtimestamp(os.path.getctime(file_path)) > start_from_date

        is_csv_file = os.path.splitext(file_path)[1] == CSV_EXTENSION
        return is_csv_file and pass_time_filter

    @staticmethod
    def get_csv_paths(csv_folder_or_file_path, order_by_time=True):
        paths = []
        if os.path.isdir(csv_folder_or_file_path):
            for dir_name in os.listdir(csv_folder_or_file_path):
                if os.path.isfile(os.path.join(csv_folder_or_file_path, dir_name)):
                    paths.append(os.path.join(csv_folder_or_file_path, dir_name))
        else:
            paths.append(csv_folder_or_file_path)

        if order_by_time:
            paths = sorted(paths, key=lambda path: os.path.getmtime(path), reverse=True)

        return paths

    def get_relevant_csv_files(self, csv_folder_or_file_path, days_back=None, csv_count_limit=None):
        """
        Return the relevant ioc's files according to time limit
        :param csv_folder_or_file_path: {string} file path or folder path
        :param days_back: {str} how many days back to look for
        :param csv_count_limit: {int} Process csv files based on the given limit in every cycle. e.g. 10
        return: {list} of strings
        """
        return [path for path in self.get_csv_paths(csv_folder_or_file_path)
                if self.is_csv_file_pass_time_filter(path, days_back)][:csv_count_limit]

    def read_csv(self, csv_path, file_encodings, file_has_header=True):
        """
        Read CSV by path
        :param csv_path: {str} full path of the csv file
        :param file_encodings: {list} List of possible CSV encodings
        :param file_has_header: {list} List of possible CSV encodings
        :return {pandas.core.frame.DataFrame}
        """
        # Encodings are a complex subject. PANDA can not infer from a CSV file what encoding it is in.
        # The problem: when reading a CSV file PANDA raises an error related to the encoding of the file.
        # The Solution: try the following encodings, in this order: utf-8, iso-8859-1 (also known as latin-1)
        # Read http://pandaproject.net/docs/determining-the-encoding-of-a-csv-file.html
        for file_encoding in file_encodings:
            try:
                read_params = {'filepath_or_buffer': csv_path, 'encoding': file_encoding}
                if not file_has_header:
                    read_params['header'] = None

                return pandas.read_csv(**read_params)
            except Exception as e:
                self.siemplify.LOGGER.error(f'Failed to read file {csv_path}. Error is {e}')
                self.siemplify.LOGGER.exception(e)
        raise CSVEncodingException(f'Failed reading file {csv_path} with all given encodings '
                                   f'{file_encodings}, please specify some other '
                                   f'encoding so we can process your files. Aborting processing file: {csv_path}')

    def search_in_csv(self, csv_content, value_to_search, searchable_columns=None, return_the_first_match=False):
        """
        Read CSV and search for value in the content
        :param csv_content: {pandas.core.frame.DataFrame}
        :param value_to_search: {str} of value to search for
        :param searchable_columns: {list} List of columns names
        :param return_the_first_match: {bool} return first matching row
        :return: {list} list of CSVItems
        """
        # Encodings are a complex subject. PANDA can not infer from a CSV file what encoding it is in.
        # The problem: when reading a CSV file PANDA raises an error related to the encoding of the file.
        # The Solution: try the following encodings, in this order: utf-8, iso-8859-1 (also known as latin-1)
        # Read http://pandaproject.net/docs/determining-the-encoding-of-a-csv-file.html
        date_frame = csv_content.applymap(get_value_for_search)

        if searchable_columns:
            searchable_columns = list(set(searchable_columns).intersection(date_frame.columns))
            date_frame = date_frame[date_frame[searchable_columns]
                .apply(lambda x: value_to_search in list(map(str, x)), axis=1)]
        else:
            date_frame = date_frame.loc[date_frame.eq(value_to_search).any(1)]

        if return_the_first_match:
            date_frame = date_frame.head(1)

        return [CSVItem(single_raw.to_dict()) for _, single_raw in date_frame.iterrows()]
