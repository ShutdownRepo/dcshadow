from calendar import timegm
from datetime import datetime

def get_ft(dt: datetime = None) -> int:
    # code taken from the winfiletime library.
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
    HUNDREDS_OF_NS = 10000000
    filetime = EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NS)
    return filetime