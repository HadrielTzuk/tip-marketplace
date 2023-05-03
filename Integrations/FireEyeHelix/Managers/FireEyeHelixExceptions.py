class FireEyeHelixException(Exception):
    pass


class FireEyeHelixNotFoundAlertException(FireEyeHelixException):
    pass


class FireEyeHelixNotFoundListException(FireEyeHelixException):
    pass


class FireEyeHelixJobNotFinishedException(FireEyeHelixException):
    pass


class FireEyeHelixJobPausedException(FireEyeHelixException):
    pass


class FireEyeHelixInvalidTimeFrameException(FireEyeHelixException):
    pass
