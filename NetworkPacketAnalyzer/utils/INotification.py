import abc


class INotification(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def send_notification(self, title, msg, icon=None):
        pass
