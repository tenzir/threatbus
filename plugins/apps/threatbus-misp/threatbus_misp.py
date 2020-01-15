import json
import warnings

warnings.simplefilter("ignore")  # pymisp produces urllib warnings
import pymisp
from queue import Queue
import threading
import zmq
from misp_message_mapping import map_to_internal, map_to_misp
import threatbus

"""MISP - Open Source Threat Intelligence Platform - plugin for Threat Bus"""

plugin_name = "misp"


def validate_config(config):
    assert config, "config must not be None"
    config["api_host"].get(str)
    config["ssl"].get(bool)
    config["api_key"].get(str)
    config["zmq"].get(object)
    config["zmq"]["host"].get(str)
    config["zmq"]["port"].get(int)


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
        misp_sighting = map_to_misp(sighting)
        misp.add_sighting(misp_sighting)


def receive(logger, misp, zmq_config, inq):
    """Binds a listener for the the given host/port to the broker ep. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param misp A connected pymisp instance
        @param zmq_config A configuration object for ZeroMQ binding
        @param inq The queue to which intel items from MISP are forwarded to
    """

    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{zmq_config['host']}:{zmq_config['port']}")
    socket.setsockopt(zmq.SUBSCRIBE, b"misp_json_attribute")
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            raw = socket.recv()
            _, message = raw.decode("utf-8").split(" ", 1)
            msg = json.loads(message)
            if not msg.get("Attribute", None):
                continue
            intel = map_to_internal(msg["Attribute"], msg.get("action", None), logger)
            if not intel:
                logger.debug(f"Discarding unparsable intel {msg['Attribute']}")
            else:
                inq.put(intel)


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
    subscribe_callback("tenzir/threatbus/sighting", outq)

    threading.Thread(
        target=receive, args=(logger, misp, config["zmq"], inq), daemon=True
    ).start()
    threading.Thread(
        target=publish_sightings, args=(logger, misp, outq), daemon=True
    ).start()
    logger.info("MISP plugin started")
