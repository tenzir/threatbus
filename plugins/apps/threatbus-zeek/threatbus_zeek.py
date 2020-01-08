from contextlib import suppress
from datetime import datetime
import broker
from queue import Queue
import select
import threading

import threatbus
from threatbus.data import Intel, Operation, Sighting

"""Zeek network monitor - plugin for Threat Bus"""

plugin_name = "zeek"
lock = threading.Lock()
subscribed_topics = set()


def validate_config(config):
    assert config, "config must not be None"
    config["host"].get(str)
    config["port"].get(int)


def map_to_string_set(topic_vector):
    """Maps a zeek vector of topics to a python set of strings."""
    if not topic_vector or type(topic_vector).__name__ != "VectorTopic":
        return set()
    return set(map(str, topic_vector))


def map_to_internal(broker_data):
    """Maps a broker message to the internal format.
        @param broker_data The raw data that was received via broker
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    if name == "sighting":
        # convert args to sighting
        return Sighting(args[0], str(args[1]), args[2])
    elif name == "intel":
        # convert args to intel
        op = Operation.ADD
        with suppress(Exception):
            op = Operation(args[3])
        return Intel(args[0], str(args[1]), args[2], op)


def map_to_broker(msg):
    """Maps the internal message format to a broker message.
        @param msg The message that shall be converted
    """
    msg_type = type(msg).__name__.lower()
    if msg_type == "sighting":
        # convert sighting to zeek event
        return broker.zeek.Event(
            "Tenzir::update_sighting", (msg.ts, str(msg.intel_id), msg.context),
        )
    elif msg_type == "intel":
        # convert intel to zeek event
        return broker.zeek.Event(
            "Tenzir::update_intel", (msg.ts, str(msg.id), msg.data, msg.operation.value)
        )


def publish(logger, ep, outq):
    """Publishes all messages that arrive via the outq to all subscribed broker topics.
        @param logger A logging.logger object
        @param ep The broker endpoint used for publishing
        @param outq The queue to forward messages from
    """
    global subscribed_topics, lock
    while True:
        msg = outq.get(block=True)
        event = map_to_broker(msg)
        lock.acquire()
        for topic in subscribed_topics:
            ep.publish(topic, event)
        lock.release()
        logger.debug(f"Zeek sent {msg}")


def listen(logger, host, port, ep, inq):
    """Binds a listener for the the given host/port to the broker ep. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param host The host (e.g., IP) to listen at
        @param port The port number to listen at
        @param ep The broker endpoint used for listening
        @param outq The queue to forward messages to
    """
    ep.listen(host, port)
    sub = ep.make_subscriber("tenzir")
    logger.info(f"Broker: endpoint listening - {host}:{port}")
    while True:
        ready = select.select([sub.fd()], [], [])
        if not ready[0]:
            logger.critical("Broker subscriber filedescriptor error.")
        (topic, broker_data) = sub.get()
        msg = map_to_internal(broker_data)
        if msg:
            inq.put(msg)


def status_update(config, logger, ep, outq, subscribe_callback, unsubscribe_callback):
    stat_sub = ep.make_status_subscriber(True)
    # broker already is a pub-sub system
    # we reuse broker topics as threat-bus topics and register all currently subscribed broker topics at the backbones
    global subscribed_topics, lock
    while True:
        ready = select.select([stat_sub.fd()], [], [])
        if not ready[0]:
            logger.critical("Status-subscriber filedescriptor error.")
        status = stat_sub.get()
        if not status:
            logger.error(
                "Encountered unknown connection status on broker receiver {status}"
            )
            continue
        lock.acquire()
        ep_subscriptions = map_to_string_set(ep.peer_subscriptions())
        if status.code() == broker.SC.PeerAdded:
            logger.info("New peer added.")
            added_topics = ep_subscriptions - subscribed_topics
            if added_topics:
                logger.info(f"New topics subscribed: {added_topics}")
                subscribed_topics = ep_subscriptions
                subscribe_callback(map(str, added_topics), outq)
        elif (
            status.code() == broker.SC.PeerRemoved
            or status.code() == broker.SC.PeerLost
        ):
            logger.info("Peer removed.")
            removed_topics = subscribed_topics - ep_subscriptions
            if removed_topics:
                logger.info(f"Topic subscriptions removed: {removed_topics}")
                subscribed_topics = ep_subscriptions
                unsubscribe_callback(map(str, removed_topics), outq)
        lock.release()


@threatbus.app
def run(config, logging, inq, subscribe_callback, unsubscribe_callback):
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        raise ValueError("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    host, port = (
        config["host"].get(),
        config["port"].get(),
    )
    broker_opts = broker.BrokerOptions()
    broker_opts.forward = False
    ep = broker.Endpoint(broker.Configuration(broker_opts))
    threading.Thread(
        target=listen, args=(logger, host, port, ep, inq), daemon=True
    ).start()
    outq = Queue()  # Single global queue. We cannot distinguish better with broker.
    threading.Thread(
        target=status_update,
        args=(config, logger, ep, outq, subscribe_callback, unsubscribe_callback),
        daemon=True,
    ).start()
    threading.Thread(target=publish, args=(logger, ep, outq), daemon=True).start()
    logger.info("Zeek plugin started")
