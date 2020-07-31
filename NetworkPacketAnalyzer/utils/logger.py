import logging


class MyLogger(object):
    def __init__(self, name, level=logging.INFO):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self.add_stream_handler(level, log_format='[%(asctime)s - %(levelname)s] %(message)s @ %(name)')

    def add_stream_handler(self, level, log_format):
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        formatter = logging.Formatter(log_format)
        stream_handler.setFormatter(formatter)
        self._logger.addHandler(stream_handler)

    def add_file_handler(self, level, log_format, filename):
        file_handler = logging.FileHandler(filename)
        file_handler.setLevel(level)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

    def debug(self, message, *args, **kwargs):
        self._logger.debug(message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self._logger.info(message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self._logger.warning(message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self._logger.error(message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        self._logger.critical(message, *args, **kwargs)
