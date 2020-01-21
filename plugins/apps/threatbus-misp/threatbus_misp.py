from confluent_kafka import Consumer, KafkaError
import json
import pymisp
from queue import Queue
import threading
import warnings
import zmq

from misp_message_mapping import map_to_internal, map_to_misp
import threatbus

warnings.simplefilter("ignore")  # pymisp produces urllib warnings

"""MISP - Open Source Threat Intelligence Platform - plugin for Threat Bus"""

plugin_name = "misp"


def validate_config(config):
    assert config, "config must not be None"
    # redact fallback values to allow for omitting configuration blocks
    config["api"].add({})
    config["zmq"].add({})
    config["kafka"].add({})
    if config["zmq"].get(dict) and config["kafka"].get(dict):
        raise AssertionError("either use ZeroMQ or Kafka, but not both")

    if config["api"].get(dict):
        config["api"]["host"].get(str)
        config["api"]["ssl"].get(bool)
        config["api"]["key"].get(str)
    if config["zmq"].get(dict):
        config["zmq"]["host"].get(str)
        config["zmq"]["port"].get(int)
    if config["kafka"].get(dict):
        config["kafka"]["topics"].get(list)
        config["kafka"]["poll_interval"].add(1.0)
        config["kafka"]["poll_interval"].get(float)
        config["kafka"]["config"].get(dict)


def publish_sightings(logger, misp, outq):
    """Reports / publishes true-positive sightings of intelligence items back to the given MISP endpoint.
        @param logger A logging.logger object
        @param misp A connected pymisp instance
        @param outq The queue from which to forward messages to MISP 
    """
    if not misp:
        return
    while True:
        sighting = outq.get(block=True)
        logger.debug(
            f"report sighting for intel id {sighting.intel} seen at {sighting.ts}"
        )
        misp_sighting = map_to_misp(sighting)
        misp.add_sighting(misp_sighting)


def receive_kafka(logger, kafka_config, inq):
    """Binds a Kafka consumer to the the given host/port. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param kafka_config A configuration object for Kafka binding
        @param inq The queue to which intel items from MISP are forwarded to
    """
    consumer = Consumer(kafka_config["config"].get(dict))
    consumer.subscribe(kafka_config["topics"].get(list))
    while True:
        message = consumer.poll(timeout=kafka_config["poll_interval"].get(float))
        if message is None:
            continue
        if message.error():
            logger.error(f"Kafka error: {message.error()}")
            continue
        try:
            msg = json.loads(message.value())
        except Exception as e:
            logger.error(f"Error decoding Kafka message: {e}")
            continue
        if not msg.get("Attribute", None):
            logger.debug("Skipping message without MISP Attribute")
            continue
        intel = map_to_internal(msg["Attribute"], msg.get("action", None), logger)
        if not intel:
            logger.debug(f"Discarding unparsable intel {msg['Attribute']}")
        else:
            inq.put(intel)


def receive_zmq(logger, zmq_config, inq):
    """Binds a ZMQ poller to the the given host/port. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param zmq_config A configuration object for ZeroMQ binding
        @param inq The queue to which intel items from MISP are forwarded to
    """

    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{zmq_config['host']}:{zmq_config['port']}")
    # TODO: allow reception of more topics, i.e. handle events.
    socket.setsockopt(zmq.SUBSCRIBE, b"misp_json_attribute")
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    while True:
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            raw = socket.recv()
            _, message = raw.decode("utf-8").split(" ", 1)
            try:
                msg = json.loads(message)
            except Exception as e:
                logger.error(f"Erro decoding message {message}: {e}")
                continue
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
    # TODO: MISP instances shall subscribe themselves to threatbus and each subscription shall have an individual outq and receiving thread for intel updates.
    outq = Queue()
    misp = None
    if config["api"].get():
        host, key, ssl = (
            config["api"]["host"].get(),
            config["api"]["key"].get(),
            config["api"]["ssl"].get(),
        )
        try:
            misp = pymisp.ExpandedPyMISP(url=host, key=key, ssl=ssl)
        except Exception as e:
            # TODO: log individual error per MISP subscriber
            logger.error(f"Cannot subscribe to MISP at {host}, using SSL: {ssl}")

    # TODO: make individual subscriptions per subscribed MISP endpoint
    subscribe_callback("tenzir/threatbus/sighting", outq)

    if misp:
        threading.Thread(
            target=publish_sightings, args=(logger, misp, outq), daemon=True
        ).start()
    if config["zmq"].get():
        threading.Thread(
            target=receive_zmq, args=(logger, config["zmq"], inq), daemon=True
        ).start()
    if config["kafka"].get():
        threading.Thread(
            target=receive_kafka, args=(logger, config["kafka"], inq), daemon=True
        ).start()
    logger.info("MISP plugin started")
