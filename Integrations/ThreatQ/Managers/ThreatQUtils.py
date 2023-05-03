from datetime import datetime
from constants import (
    HAPPENED_AT_DATETIME_DEFAULT_FORMAT
)

def validate_time_format(date_text):
    """
    Check of time format
    @param date_text: Specified date as string
    @return None or Exception
    """
    try:
        datetime.strptime(date_text, HAPPENED_AT_DATETIME_DEFAULT_FORMAT)
    except ValueError:
        raise ValueError("Incorrect time format was passed to \'Happened At\' action parameter. Should be YYYY-MM-DD hh:mm:ss.")
    
    
    
    
