"""
The notifier for Linux systems.
"""

import notify2
from utils.INotification import INotification


_APP_NAME = 'NetworkPacketAnalyzer'


class NotifierLinux(INotification):
    """
    The notifier in Linux (Tested in GNOME, has not been tested on other platforms yet).

    Parameters
    ----------
    title : str
        The title of notification.
    msg : str
        The message content.
    icon : str, optional
        The path of the icon.
    timeout : int, default 5
        The time of notification appearing.
    urgency : {notify2.URGENCY_LOW, notify2.URGENCY_NORMAL, notify2.URGENCY_CRITICAL}, default notify2.URGENCY_NORMAL
        The message urgency.

    Attributes
    ----------
    _notifier : notify2.Notification
        The notifier.
    """
    def __init__(self, title='', msg='', icon='', timeout=5, urgency=notify2.URGENCY_NORMAL):
        notify2.init(_APP_NAME)
        self._notifier = notify2.Notification(title, msg, icon)
        self._notifier.set_urgency(urgency)
        self._notifier.set_timeout(timeout)

    def send_notification(self, title, msg, icon=None):
        """
        Send notification to the system.

        Parameters
        ----------
        title : str
            The title of the notification.
        msg : str
            The message content.
        icon : str, optional
            The path of the icon.
        """
        self._notifier.summary = title
        self._notifier.message = msg
        self._notifier.icon = icon
        self._notifier.show()
