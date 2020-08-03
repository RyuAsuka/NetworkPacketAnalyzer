"""
This module defines a simple enum class `FlowStatus`.
"""


class FlowStatus(object):
    """
    The FlowStatus enum.
    """
    ACTIVE = 0
    FIN_WAIT_1 = 1
    FIN_WAIT_2 = 2
    CLOSING = 3
    CLOSE_WAIT = 4
    LAST_ACK = 5
    TIME_WAIT = 6
