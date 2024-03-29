import coloredlogs
from dynaconf.utils.boxing import DynaBox
import logging
import sys


def setup(config: DynaBox, name: str):
    fmt = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
    colored_formatter = coloredlogs.ColoredFormatter(fmt)
    plain_formatter = logging.Formatter(fmt)
    logger = logging.getLogger(name)
    if config.file:
        fh = logging.FileHandler(config.filename)
        fhLevel = logging.getLevelName(config.file_verbosity.upper())
        logger.setLevel(fhLevel)
        fh.setLevel(fhLevel)
        fh.setFormatter(plain_formatter)
        logger.addHandler(fh)
    if config.console:
        ch = logging.StreamHandler()
        chLevel = logging.getLevelName(config.console_verbosity.upper())
        ch.setLevel(chLevel)
        if logger.level > chLevel or logger.level == 0:
            logger.setLevel(chLevel)
        ch.setFormatter(colored_formatter)
        logger.addHandler(ch)

    class ShutdownHandler(logging.Handler):
        """Exit application with CRITICAL logs"""

        def emit(self, record):
            logging.shutdown()
            sys.exit(1)

    sh = ShutdownHandler(level=50)
    sh.setFormatter(colored_formatter)
    logger.addHandler(sh)
    return logger
