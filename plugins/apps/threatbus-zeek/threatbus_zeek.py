from datetime import datetime
import broker
from queue import Queue
import select
import threading

import threatbus

"""Zeek network monitor - plugin for Threat Bus"""

plugin_name = "zeek"
lock = threading.Lock()
subscribed_topics = set()


def validate_config(config):
    assert config, "config must not be None"
    config["host"].get(str)
    config["port"].get(int)


def map_to_internal(broker_data):
    """Maps a broker message to the internal format.
        @param broker_data The raw data that was received via broker
    """
    event = broker.zeek.Event(broker_data)
    name, args = event.name(), event.args()
    if name == "sighting":
        # convert args to sighting
        return threatbus.data.Sighting(
            datetime.fromtimestamp(args[0]), args[1], args[2]
        )
    elif name == "intel":
        # convert args to intel
        return threatbus.data.Intel(datetime.fromtimestamp(args[0]), args[1], args[2])


def map_to_broker(msg):
    """Maps the internal message format to a broker message.
        @param msg The message that shall be converted
    """
    msg_type = type(msg).__name__.lower()
    if msg_type == "sighting":
        # convert sighting to zeek event
        return broker.zeek.Event(
            "sighting", datetime.timestamp(msg.ts), msg.intel_id, msg.context
        )
    elif msg_type == "intel":
        # convert intel to zeek event
        return broker.zeek.Event("intel", datetime.timestamp(msg.ts), msg.id, msg.data)


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
    sub = ep.make_subscriber("")
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
        if status.code() == broker.SC.PeerAdded:
            topics = set(ep.peer_subscriptions()) - subscribed_topics
            if topics:
                subscribed_topics = set(ep.peer_subscriptions())
                subscribe_callback(map(str, topics), outq)
        elif (
            status.code() == broker.SC.PeerRemoved
            or status.code() == broker.SC.PeerLost
        ):
            topics = subscribed_topics - set(ep.peer_subscriptions())
            if topics:
                subscribed_topics = set(ep.peer_subscriptions())
                unsubscribe_callback(map(str, topics), outq)
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
