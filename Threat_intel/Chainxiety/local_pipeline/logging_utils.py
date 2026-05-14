import logging
import os

from .config import DATA_DIR


def setup_logging(name):
    os.makedirs(DATA_DIR, exist_ok=True)
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_path = os.environ.get("LOG_FILE", os.path.join(DATA_DIR, "pipeline.log"))

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, log_level, logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger
