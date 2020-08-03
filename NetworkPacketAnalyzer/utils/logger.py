"""
The logger class, which encapsulated built-in module `logging`.
"""


import logging


class MyLogger(object):
    """
    The logger class.

    Parameters
    ----------
    name : str
        The name of logger object. It is suggested to use the nanme of module or class which uses the logger.
    level : int or str, default logging.INFO
        The logging level. The default value is logging.INFO or 'INFO'.

    Attributes
    ----------
    _logger : logging.RootLogger
        The inner logger originated from `logging` module.

    Examples
    --------
    >>> logger1 = MyLogger('main')
    >>> logger2 = MyLogger('logger2', level='DEBUG')

    See Also
    --------
    logging : The origin `logging` module of Python.

    Notes
    -----
    The common format of log format:

    +----------------+-------------------------------------+
    | Format         | Description                         |
    +================+=====================================+
    | %(levelno)s    | Print level number.                 |
    +----------------+-------------------------------------+
    | %(levelname)s  | Print level name.                   |
    +----------------+-------------------------------------+
    | %(pathname)s   | Print the path of current programme.|
    +----------------+-------------------------------------+
    | %(filename)s   | Print the name of current programme.|
    +----------------+-------------------------------------+
    | %(funcName)s   | Print the name of current function. |
    +----------------+-------------------------------------+
    | %(lineno)s     | Print the number of current line.   |
    +----------------+-------------------------------------+
    | %(asctime)s    | Print the time when logging.        |
    +----------------+-------------------------------------+
    | %(thread)d     | Print the thread ID.                |
    +----------------+-------------------------------------+
    | %(threadName)s | Print the name of current thread.   |
    +----------------+-------------------------------------+
    | %(process)d    | Print the current process ID.       |
    +----------------+-------------------------------------+
    | %(message)s    | Print the log message.              |
    +----------------+-------------------------------------+
    """
    def __init__(self, name, level=logging.INFO):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self.add_stream_handler(level, log_format='[%(asctime)s - %(levelname)s] @ %(name)s %(message)s')

    def add_stream_handler(self, level, log_format):
        """
        Add a stream handler to the logger.

        Parameters
        ----------
        level : int or str
            The log level of this handler.
        log_format : str
            The log format.
        """
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        formatter = logging.Formatter(log_format)
        stream_handler.setFormatter(formatter)
        self._logger.addHandler(stream_handler)

    def add_file_handler(self, level, log_format, filename):
        """
        Add a file handler to the logger.

        The file handler enables the logger can put the logs into a file.

        Parameters
        ----------
        level : int or str
            The log level of this handler.
        log_format : str
            The log format.
        filename : str
            The output log filename.
        """
        file_handler = logging.FileHandler(filename)
        file_handler.setLevel(level)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

    def debug(self, message, *args, **kwargs):
        """
        Log 'message % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        Parameters
        ----------
        message : str
            The message of debug information.
        args
            The variables used in the debug information.
        kwargs
            Other parameters.

        Other Parameters
        ----------------
        exc_info : {0, 1}, default 0
            Whether to pass exception information.
        """
        self._logger.debug(message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        """
        Log 'message % args' with severity 'INFO'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        Parameters
        ----------
        message : str
            The message of normal information.
        args
            The variables used in the normal information.
        kwargs
            Other parameters.

        Other Parameters
        ----------------
        exc_info : {0, 1}, default 0
            Whether to pass exception information.
        """
        self._logger.info(message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        """
        Log 'message % args' with severity 'WARNING'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        Parameters
        ----------
        message : str
            The message of warning information.
        args
            The variables used in the warning information.
        kwargs
            Other parameters.

        Other Parameters
        ----------------
        exc_info : {0, 1}, default 0
            Whether to pass exception information.
        """
        self._logger.warning(message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        """
        Log 'message % args' with severity 'ERROR'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        Parameters
        ----------
        message : str
            The message of error information.
        args
            The variables used in the error information.
        kwargs
            Other parameters.

        Other Parameters
        ----------------
        exc_info : {0, 1}, default 0
            Whether to pass exception information.
        """
        self._logger.error(message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        """
        Log 'message % args' with severity 'CRITICAL'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)

        Parameters
        ----------
        message : str
            The message of critical error information.
        args
            The variables used in the critical error information.
        kwargs
            Other parameters.

        Other Parameters
        ----------------
        exc_info : {0, 1}, default 0
            Whether to pass exception information.
        """
        self._logger.critical(message, *args, **kwargs)
