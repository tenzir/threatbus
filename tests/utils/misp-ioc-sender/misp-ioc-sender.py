#!/usr/bin/env python3

import argparse
import coloredlogs
import confuse
from datetime import datetime
import logging
import pymisp
import sys
import warnings

# pymisp produces urllib warnings and has very verbose logging.
warnings.simplefilter("ignore")
logging.getLogger("pymisp").setLevel(logging.CRITICAL)
logger = None


def setup_logging(config: confuse.Subview, name: str):
    """
    Sets up the logging for this script, according to the given configuration
    object. Logging can go to a file, to console, or both.
    Logs are colored. Critical logs make the script exit with exitcode 1.
    @param config The configuration object to setup logging
    @param name The name of the logger
    """
    fmt = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
    colored_formatter = coloredlogs.ColoredFormatter(fmt)
    plain_formatter = logging.Formatter(fmt)
    logger = logging.getLogger(name)
    if config["file"]:
        fh = logging.FileHandler(config["filename"].get(str))
        fhLevel = logging.getLevelName(config["file_verbosity"].get(str).upper())
        logger.setLevel(fhLevel)
        fh.setLevel(fhLevel)
        fh.setFormatter(plain_formatter)
        logger.addHandler(fh)
    if config["console"]:
        ch = logging.StreamHandler()
        chLevel = logging.getLevelName(config["console_verbosity"].get(str).upper())
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


def connect_misp(host: str, key: str, ssl: bool):
    """
    Connects to a MISP instance. Returns the pymisp.MISP object.
    @param host The MISP URL to connect to
    @param key The MISP API key
    @param ssl Boolean flag to use SSL
    """
    try:
        return pymisp.ExpandedPyMISP(url=host, key=key, ssl=ssl)
    except Exception:
        logger.ciritcal(f"Cannot connect to MISP at '{host}', using SSL '{ssl}'")


def get_or_create_event(misp: pymisp.api.PyMISP, event_uuid: str):
    """
    Returns a MISP Event with the given UUID. Creates a new event with the given
    UUID if it does not exist yet.
    @param misp The PyMISP instance to use
    @param event_uuid The Event UUID to fetch or create
    """
    misp_event = pymisp.MISPEvent()
    misp_event.uuid = event_uuid
    event = misp.get_event(misp_event, deleted=False, pythonify=True)
    if not event or event.get("errors", None):
        logger.warn(f"Could not fetch MISP event with UUID {event_uuid}.")
        misp_event.info = "Retro-Matching roundtrip test event"
        event = misp.add_event(misp_event, pythonify=True)
        if not event or event.get("errors", None):
            errors = event.get("errors", {})
            logger.critical(
                f"Error creating new event. Make sure the configured UUID is not already deleted in MISP: {errors}"
            )
        logger.info(f"Created new MISP event with UUID '{event.uuid}'.")
    else:
        logger.info(f"Found MISP event with UUID '{event.uuid}'")
    return event


def get_todays_attribute():
    """
    Returns a string indicator in the format `test-$YYYY-%mm-%dd.vast`
    """
    return f"test-{datetime.now().strftime('%Y-%m-%d')}.vast"


def create_attribute(misp: pymisp.api.PyMISP, event: pymisp.MISPEvent, ioc: str):
    """
    Creates a new MISP Attribute with the given 'ioc' string for the given MISP
    Event.
    @param misp The PyMISP instance to use
    @param event the MISP Event to create the Attribute for
    @param ioc The desired Attribute value
    """
    attr = pymisp.MISPAttribute()
    attr.type = "domain"
    attr.value = ioc
    attr = misp.add_attribute(event, attr, pythonify=True)
    if not attr or attr.get("errors", {}):
        errors = attr.get("errors", {})
        logger.critical(f"Error creating MISP Attribute with IoC {ioc}: {errors}")
        return
    logger.info(f"Created new MISP Attribute with IoC '{ioc}'")


def toggle_attribute(misp: pymisp.api.PyMISP, attr: pymisp.MISPAttribute):
    """
    First turns off the 'to_ids' flag for the given MISP Attribute, then turns
    it on. Once this function exits, the Attribute will always be left with
    'to_ids' enabled.
    @param misp The PyMISP instance to use
    @param attr The MISP Attribute to toggle
    """
    attr.to_ids = False
    resp = misp.update_attribute(attr)
    if not resp or resp.get("errors", {}):
        logger.error(f"Error disabling 'to_ids' flag for Attribute {attr}")
    attr.to_ids = True
    resp = misp.update_attribute(attr)
    if not resp or resp.get("errors", {}):
        logger.error(f"Error enabling 'to_ids' flag for Attribute {attr}")
    logger.info(f"Toggled 'to_ids' flag for Attibute {attr}")


def start(config: confuse.Subview):
    """
    Connects to MISP and makes it so that a DOMAIN-type indicator with the
    format `test-%YYYY-%mm-%dd.vast` appears to be added to MISP. Creates all
    required resources, if necessary.
    @param config The user-defined configuration object
    """
    global logger
    logger = setup_logging(config["logging"], "misp-ioc-sender")

    host, key, ssl = (
        config["misp"]["host"].get(),
        config["misp"]["key"].get(),
        config["misp"]["ssl"].get(),
    )
    event_uuid = config["event-uuid"].get()
    misp = connect_misp(host, key, ssl)
    event = get_or_create_event(misp, event_uuid)
    ioc = get_todays_attribute()
    attrs = [
        attr
        for attr in event.get("Attribute", {})
        if attr.to_dict().get("value", None) == ioc
    ]
    if not attrs:
        create_attribute(misp, event, ioc)
    elif len(attrs) == 1:
        logger.info(f"Found MISP Attribute with IoC '{ioc}'")
        toggle_attribute(misp, attrs[0])
    else:
        logger.critical(
            f"Found too many matching attributes for IoC '{ioc}' in the MISP event with UUID {event_uuid}"
        )


def main():
    config = confuse.Configuration("misp-ioc-sender")
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    config.set_args(args)
    if args.config:
        config.set_file(args.config)
    start(config)


if __name__ == "__main__":
    main()
