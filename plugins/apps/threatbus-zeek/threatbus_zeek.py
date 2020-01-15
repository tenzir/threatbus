import broker
from zeek_message_mapping import map_to_broker, map_to_internal, map_to_string_set
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
    config["module_namespace"].get(str)


def publish(logger, module_namespace, ep, outq):
    """Publishes all messages that arrive via the outq to all subscribed broker topics.
        @param logger A logging.logger object
        @param module_namespace A Zeek namespace to use for event sending
        @param ep The broker endpoint used for publishing
        @param outq The queue to forward messages from
    """
    global subscribed_topics, lock
    while True:
        msg = outq.get(block=True)
        msg_type = type(msg).__name__.lower()
        msg_types = ["intel", "sighting"]
        event = map_to_broker(msg, module_namespace)
        lock.acquire()
        for topic in subscribed_topics:
            if topic.endswith(msg_type) or all([t not in topic for t in msg_types]):
                ep.publish(topic, event)
        lock.release()
        logger.debug(f"Published {msg}")


def listen(logger, host, port, module_namespace, ep, inq):
    """Binds a listener for the the given host/port to the broker ep. Forwards all received messages to the inq.
        @param logger A logging.logger object
        @param host The host (e.g., IP) to listen at
        @param port The port number to listen at
        @param module_namespace A Zeek namespace to accept events from
        @param ep The broker endpoint used for listening
        @param inq The queue to forward messages to
    """
    ep.listen(host, port)
    sub = ep.make_subscriber("tenzir")
    logger.info(f"Broker: endpoint listening - {host}:{port}")
    while True:
        ready = select.select([sub.fd()], [], [])
        if not ready[0]:
            logger.critical("Broker subscriber filedescriptor error.")
        (topic, broker_data) = sub.get()
        msg = map_to_internal(broker_data, module_namespace)
        if msg:
            inq.put(msg)


def status_update(config, logger, ep, outq, subscribe_callback, unsubscribe_callback):
    stat_sub = ep.make_status_subscriber(True)
    # broker already is a pub-sub system
    # we reuse broker topics as Threat Bus topics and register all currently subscribed broker topics at the backbones
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
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    host, port, namespace = (
        config["host"].get(),
        config["port"].get(),
        config["module_namespace"].get(),
    )
    broker_opts = broker.BrokerOptions()
    broker_opts.forward = False
    ep = broker.Endpoint(broker.Configuration(broker_opts))
    threading.Thread(
        target=listen, args=(logger, host, port, namespace, ep, inq), daemon=True
    ).start()
    outq = Queue()  # Single global queue. We cannot distinguish better with broker.
    threading.Thread(
        target=status_update,
        args=(config, logger, ep, outq, subscribe_callback, unsubscribe_callback),
        daemon=True,
    ).start()
    threading.Thread(
        target=publish, args=(logger, namespace, ep, outq), daemon=True
    ).start()
    logger.info("Zeek plugin started")
