from datetime import datetime
import warnings

warnings.simplefilter("ignore")
import pymisp
from queue import Queue
import threading
import time

import threatbus
from threatbus.data import Intel, Operation, Sighting

"""MISP - Open Source Threat Intelligence Platform - plugin for Threat Bus"""

plugin_name = "misp"


def validate_config(config):
    assert config, "config must not be None"
    config["api_host"].get(str)
    config["ssl"].get(bool)
    config["api_key"].get(str)


def map_to_intel(misp_attribute):
    """Maps the given MISP attribute to the threatbus intel format.
        @param misp_attribute A MISP attribute
    """
    # TODO: threatbus defines intel types that zeek can use as well.
    # intel_type = map_misp_intel_type(misp_attribute["type"])
    intel_type = "DOMAIN"
    data = {
        "indicator": misp_attribute["value"],
        "intel_type": intel_type,
        "source": "MISP",
    }
    return Intel(
        datetime.fromtimestamp(int(misp_attribute["timestamp"])),
        str(misp_attribute["id"]),
        data,
        Operation.ADD,
    )


def map_to_misp(sighting):
    """Maps the threatbus sighting format to a MISP sighting.
        @param sighting A threatbus Sighting object
    """
    misp_sighting = pymisp.MISPSighting()
    misp_sighting.from_dict(
        id=sighting.intel,
        source=sighting.context.get("source", None),
        type="0",
        timestamp=sighting.ts,
    )
    return misp_sighting


def publish_sightings(logger, misp, outq):
    """Reports / publishes true-positive sightings of intelligence items back to the given MISP endpoint.
        @param logger A logging.logger object
        @param misp A connected pymisp instance
        @param outq The queue from which to forward messages to MISP 
    """
    while True:
        sighting = outq.get(block=True)

        logger.debug(
            f"report sighting for intel id {sighting.intel} seen at {sighting.ts}"
        )
        misp.add_sighting(misp_sighting)


def receive(logger, misp, inq):
    """Binds a listener for the the given host/port to the broker ep. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param misp A connected pymisp instance
        @param inq The queue to which intel items from MISP are forwarded to
    """
    while True:
        data = misp.search(controller="attributes", to_ids=True)
        if not data:
            continue
        for attr in data["Attribute"]:
            msg = map_to_intel(attr)
            if msg:
                inq.put(msg)
        time.sleep(5)


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    api_host, api_key, ssl = (
        config["api_host"].get(),
        config["api_key"].get(),
        config["ssl"].get(),
    )
    # TODO: MISP instances shall subscribe themselves to threatbus and each subscription shall have an individual outq and receiving thread for intel updates.
    outq = Queue()
    misp = None
    try:
        misp = pymisp.ExpandedPyMISP(url=api_host, key=api_key, ssl=ssl)
    except Exception as e:
        # TODO: log individual error per MISP subscriber, do not use fatal / do not stop threatbus
        logger.fatal(f"Cannot subscribe to MISP at {api_host}, using SSL: {ssl}")

    # TODO: make individual subscriptions per subscribed MISP endpoint
    subscribe_callback("sighting", outq)

    threading.Thread(target=receive, args=(logger, misp, inq), daemon=True).start()
    threading.Thread(
        target=publish_sightings, args=(logger, misp, outq), daemon=True
    ).start()
    logger.info("MISP plugin started")
