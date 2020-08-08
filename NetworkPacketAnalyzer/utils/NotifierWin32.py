"""
A notifier to the Windows system.

You can use the notifier at the place you need.
When the notifier is invoked, the operating system will
popup a window to inform you the work is done.
"""
from win10toast import ToastNotifier
from utils.INotification import INotification


class NotifierWin32(INotification):
    """
    The notifier for Windows 10. (Windows 7 and below are not supported)

    The notifier implements `INotification` interface.

    Parameters
    ----------
    title : str
        The message title.
    msg : str
        The main content of message.
    icon : str, optional
        The icon path.
    duration : int, default 5
        The time of the notification appearing.
    threaded : bool, default False
        If true, the notification is multithreaded.

    Attributes
    ----------
    _notifier : ToastNotifier
        The notifier.
    title : str
        The message title.
    msg : str
        The message content.
    icon : str
        The path of the icon.
    duration : int
        The time of the notification appearing.
    threaded : bool
        The multithread flag.
    """
    def __init__(self, title='', msg='', icon=None, duration=5, threaded=False):
        self._notifier = ToastNotifier()
        self.title = title
        self.msg = msg
        self.icon = icon
        self.duration = duration
        self.threaded = threaded

    def send_notification(self, title, msg, icon=None):
        """
        Send the notification to the system.

        Parameters
        ----------
        title : str
            The title of the notification.
        msg : str
            The message content.
        icon : str, optional
            The path of the icon.
        """
        self.title = title
        self.msg = msg
        self.icon = icon
        self._notifier.show_toast(title, msg, icon, self.duration, self.threaded)
