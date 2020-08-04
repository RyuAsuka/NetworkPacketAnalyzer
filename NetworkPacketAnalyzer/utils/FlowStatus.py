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

    code_to_str = {
        0: 'ACTIVE',
        1: 'FIN_WAIT_1',
        2: 'FIN_WAIT_2',
        3: 'CLOSING',
        4: 'CLOSE_WAIT',
        5: 'LAST_ACK',
        6: 'TIME_WAIT'
    }
