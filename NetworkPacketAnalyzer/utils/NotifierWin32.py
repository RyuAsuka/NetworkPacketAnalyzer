"""
A notifier to the Windows system.

You can use the notifier at the place you need.
When the notifier is invoked, the operating system will
popup a window to inform you the work is done.
"""
from win10toast import ToastNotifier
from utils.INotification import INotification


class NotifierWin32(INotification):
    def __init__(self, title='', msg='', icon=None, duration=5, threaded=False):
        self._notifier = ToastNotifier()
        self.title = title
        self.msg = msg
        self.icon = icon
        self.duration = duration
        self.threaded = threaded

    def send_notification(self, title, msg, icon=None):
        self.title = title
        self.msg = msg
        self.icon = icon
        self._notifier.show_toast(title, msg, icon, self.duration, self.threaded)
