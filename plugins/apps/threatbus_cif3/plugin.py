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
    if config["api"].get(dict):
        config["api"]["host"].get(str)
        config["api"]["ssl"].get(bool)
        config["api"]["token"].get(str)


def receive_intel_from_backbone(watched_queue, cif, config):
    """Reports / publishes intel items back to the given CIF endpoint.
        @param watched_queue The py queue from which to read messages to submit on to CIF
    """
    global logger
    logger.debug(
        "Waiting for intel from Threat Bus..."
    )
    if not cif:
        logger.error("No global CIF found. Exiting function")
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
            logger.debug("Received unparsable intel item")
            continue
        cif_mapped_intel = map_to_cif(intel, logger, confidence, tags, tlp, group)
        if not cif_mapped_intel:
            continue
        logger.debug(f"Adding intel to CIF: {cif_mapped_intel}")
        try:
            resp = cif.indicators_create(cif_mapped_intel)
            logger.debug(f"CIF response: {resp}")
        except Exception as err:
            logger.error(f"CIF submission error: {err}")


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    logger.info("Reading config file for CIF3 host, token, and ssl values")
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))

    if config["api"].get():
        remote, token, ssl = (
            config["api"]["host"].get(),
            config["api"]["token"].get(),
            config["api"]["ssl"].get(),
        )
        cif = None
        try:
            cif = Client(remote=remote, token=token, verify_ssl=ssl)
            cif.ping()
            logger.debug(f"Started CIF client to remote {remote}")
        except Exception as err:
            logger.error(
                f"Cannot connect CIF client to {remote}, using SSL: {ssl} : {err}"
            )
        
        if not cif:
            logger.error("Could not connect to CIF, existing CIF plugin")
            return

    # establish a py queue to accept queue.put from the backbone
    from_backbone_to_cifq = Queue()
    topic = "threatbus/intel"  # topic used by MISP when it sends to backbone
    subscribe_callback(topic, from_backbone_to_cifq)
    logger.debug(f"CIF plugin subscribed to topic {topic}")

    threading.Thread(
        target=receive_intel_from_backbone,
        args=[from_backbone_to_cifq, cif, config],
        daemon=True,
    ).start()
    logger.debug("Started CIF thread to monitor future Intel from backbone...")

    logger.info("CIF3 plugin started")
