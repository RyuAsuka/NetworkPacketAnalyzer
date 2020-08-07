"""
The notifier for Linux systems.
"""

import notify2
from utils.INotification import INotification


_APP_NAME = 'NetworkPacketAnalyzer'


class NotifierLinux(INotification):
    def __init__(self, title='', msg='', icon='', timeout=5, urgency=notify2.URGENCY_NORMAL):
        notify2.init(_APP_NAME)
        self._notifier = notify2.Notification(title, msg, icon)
        self._notifier.set_urgency(urgency)
        self._notifier.set_timeout(timeout)

    def send_notification(self, title, msg, icon=None):
        self._notifier.summary = title
        self._notifier.message = msg
        self._notifier.icon = icon
        self._notifier.show()
