"""
Implements the classes representing the error codes described by
https://datatracker.ietf.org/doc/html/rfc8210#section-12 .

The classes are used to raise errors within rtr.py .
"""


class PDUError(Exception):
    """
    Base class for exception handling

    Arguments:
    ----------
    message: str
        The error message
    buffer: bytes
        The content of the PDU that triggered the error. Default: bytes()
    """

    code: int
    fatal: bool
    message: str
    buffer: bytes

    def __init__(self, message: str, buffer: bytes = bytes()):
        super().__init__(message)

        self.message = message
        self.buffer = buffer


class CorruptDataError(PDUError):
    """
    Raised when the receiver believes the received PDU to be corrupt in a manner not specified by
    another error code.
    """

    code: int = 0
    fatal: bool = True


class InternalError(PDUError):
    """
    Raised when the party reporting the error experienced some kind of internal error unrelated to
    protocol operation (ran out of memory, a coding assertion failed, et cetera).
    """

    code: int = 1
    fatal: bool = True


class NoDataAvailableError(PDUError):
    """
    Raised when the cache believes itself to be in good working order but is unable to answer either
    a Serial Query or a Reset Query because it has no useful data available at this time.
    This is likely to be a temporary error and most likely indicates that the cache has not yet
    completed pulling down an initial current data set from the Global RPKI system after some kind
    of event that invalidated whatever data it might have previously held (reboot, network
    partition, et cetera).
    """

    code: int = 2
    fatal: bool = False


class InvalidRequestError(PDUError):
    """
    Raised when the cache server believes the client's request to be invalid.
    """

    code: int = 3
    fatal: bool = True


class UnsupportedProtocolVersionError(PDUError):
    """
    Raised when the Protocol Version is not known by the receiver of the PDU.
    """

    code: int = 4
    fatal: bool = True


class UnsupportedPDUTypeError(PDUError):
    """
    Raised when the PDU Type is not known by the receiver of the PDU.
    """

    code: int = 5
    fatal: bool = True


class WithdrawalofUnknownRecordError(PDUError):
    """
    Raised when the received PDU has Flag=0, but a matching record ({Prefix, Len, Max-Len, ASN}
    tuple for an IPvX PDU or {SKI, ASN, Subject Public Key} tuple for a Router Key PDU) does not
    exist in the receiver's database.
    """

    code: int = 6
    fatal: bool = True


class DuplicateAnnouncementReceivedError(PDUError):
    """
    Raised when the received PDU has Flag=1, but a matching record ({Prefix, Len, Max-Len, ASN}
    tuple for an IPvX PDU or {SKI, ASN, Subject Public Key} tuple for a Router Key PDU) is already
    active in the router.
    """

    code: int = 7
    fatal: bool = True


class UnexpectedProtocolVersionError(PDUError):
    """
    Raised when the received PDU has a Protocol Version field that differs from the protocol
    version negotiated.
    """

    code: int = 8
    fatal: bool = True
