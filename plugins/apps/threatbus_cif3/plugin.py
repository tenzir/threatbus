from queue import Queue
import threading
from cifsdk.client.http import HTTP as Client

from threatbus_cif3.message_mapping import map_to_cif
import threatbus

"""Threatbus - Open Source Threat Intelligence Platform - plugin for CIFv3"""

plugin_name = "cif3"


def validate_config(config):
    assert config, "config must not be None"
    config["tags"].get(list)
    config["tlp"].get(str)
    config["confidence"].as_number()
    config["group"].get(str)
    config["api"].get(dict)
    config["api"]["host"].get(str)
    config["api"]["ssl"].get(bool)
    config["api"]["token"].get(str)


def receive_intel_from_backbone(watched_queue, cif, config):
    """Reports / publishes intel items back to the given CIF endpoint.
        @param watched_queue The py queue from which to read messages to submit on to CIF
    """
    global logger
    if not cif:
        logger.error("CIF is not properly configured. Exiting.")
        return

    confidence = config["confidence"].as_number()
    if not confidence:
        confidence = 5

    tags = config["tags"].get(list)
    tlp = config["tlp"].get(str)
    group = config["group"].get(str)

    while True:
        intel = watched_queue.get()
        if not intel:
            logger.warning("Received unparsable intel item")
            continue
        cif_mapped_intel = map_to_cif(intel, logger, confidence, tags, tlp, group)
        if not cif_mapped_intel:
            logger.warning("Could not map intel item")
            continue
        try:
            logger.debug(f"Adding intel to CIF: {cif_mapped_intel}")
            cif.indicators_create(cif_mapped_intel)
        except Exception as err:
            logger.error(f"CIF submission error: {err}")


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))

    remote, token, ssl = (
        config["api"]["host"].get(),
        config["api"]["token"].get(),
        config["api"]["ssl"].get(),
    )
    cif = None
    try:
        cif = Client(remote=remote, token=token, verify_ssl=ssl)
        cif.ping()
    except Exception as err:
        logger.error(
            f"Cannot connect to CIFv3 at {remote}, using SSL: {ssl}. Exiting plugin."
        )
        return

    from_backbone_to_cifq = Queue()
    topic = "threatbus/intel"
    subscribe_callback(topic, from_backbone_to_cifq)

    threading.Thread(
        target=receive_intel_from_backbone,
        args=[from_backbone_to_cifq, cif, config],
        daemon=True,
    ).start()

    logger.info("CIF3 plugin started")
