from collections import defaultdict
import json
import pika
from retry import retry
from socket import gethostname
import threading
import threatbus
from threatbus.data import (
    Intel,
    Sighting,
    SnapshotRequest,
    SnapshotEnvelope,
    IntelEncoder,
    IntelDecoder,
    SightingEncoder,
    SightingDecoder,
    SnapshotRequestEncoder,
    SnapshotRequestDecoder,
    SnapshotEnvelopeEncoder,
    SnapshotEnvelopeDecoder,
)


"""RabbitMQ backbone plugin for Threat Bus"""

plugin_name = "rabbitmq"

subscriptions = defaultdict(set)
lock = threading.Lock()


def get_queue_name(join_symbol, data_type, suffix=gethostname()):
    """
    Returns a queue name accroding to the desired pattern.
    @param join_symbol The symbol to use when concatenating the name
    @param data_type The type of data that goes through the queue (e.g., "intel")
    @param suffix A suffix to append to the name. Default: the hostname
    """
    return join_symbol.join(["threatbus", data_type, suffix])


def get_exchange_name(join_symbol, data_type):
    """
    Returns an exchange name accroding to the desired pattern.
    @param join_symbol The symbol to use when concatenating the name
    @param data_type The type of data that goes through the queue (e.g., "intel")
    @param suffix A suffix to append to the name. Default: the hostname
    """
    return join_symbol.join(["threatbus", data_type])


def validate_config(config):
    assert config, "config must not be None"
    config["host"].get(str)
    config["port"].get(int)
    config["username"].get(str)
    config["password"].get(str)
    config["vhost"].get(str)
    config["naming_join_pattern"].get(str)
    config["queue"].get(dict)
    config["queue"]["name_suffix"].add("")  # optional
    config["queue"]["name_suffix"].get(str)
    config["queue"]["durable"].get(bool)
    config["queue"]["auto_delete"].get(bool)
    config["queue"]["lazy"].get(bool)
    config["queue"]["exclusive"].get(bool)
    config["queue"]["max_items"].add(0)  # optional
    config["queue"]["max_items"].get(int)


def __provision(topic, msg):
    """
    Provisions the given `msg` to all subscribers of `topic`.
    @param topic The topic string to use for provisioning
    @param msg The message to provision
    """
    global subscriptions, lock, logger
    lock.acquire()
    for t in filter(lambda t: str(topic).startswith(str(t)), subscriptions.keys()):
        for outq in subscriptions[t]:
            outq.put(msg)
    lock.release()
    logger.debug(f"Relayed message from RabbitMQ: {msg}")


def __decode(msg, decoder):
    """
    Decodes a JSON message with the given decoder. Returns the decoded object or
    None and logs an error.
    @param msg The message to decode
    @param decoder The decoder class to use for decoding
    """
    global logger
    try:
        return json.loads(msg, cls=decoder)
    except Exception as e:
        logger.error(f"Error decoding message {msg}: {e}")
        return None


def __provision_intel(channel, method_frame, header_frame, body):
    """
    Callback to be invoked by the Pika library whenever a new message `body` has
    been received from RabbitMQ on the intel queue.
    @param channel: pika.Channel The channel that was received on
    @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
    @param properties: pika.spec.BasicProperties Pika properties
    @param body: bytes The received message
    """
    msg = __decode(body, IntelDecoder)
    if msg:
        __provision("threatbus/intel", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def __provision_sighting(channel, method_frame, header_frame, body):
    """
    Callback to be invoked by the Pika library whenever a new message `body` has
    been received from RabbitMQ on the sighting queue.
    @param channel: pika.Channel The channel that was received on
    @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
    @param properties: pika.spec.BasicProperties Pika properties
    @param body: bytes The received message
    """
    msg = __decode(body, SightingDecoder)
    if msg:
        __provision("threatbus/sighting", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def __provision_snapshot_request(channel, method_frame, header_frame, body):
    """
    Callback to be invoked by the Pika library whenever a new message `body` has
    been received from RabbitMQ on the snapshot-request queue.
    @param channel: pika.Channel The channel that was received on
    @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
    @param properties: pika.spec.BasicProperties Pika properties
    @param body: bytes The received message
    """
    msg = __decode(body, SnapshotRequestDecoder)
    if msg:
        __provision("threatbus/snapshotrequest", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def __provision_snapshot_envelope(channel, method_frame, header_frame, body):
    """
    Callback to be invoked by the Pika library whenever a new message `body` has
    been received from RabbitMQ on the snapshot-envelope queue.
    @param channel: pika.Channel The channel that was received on
    @param method: pika.spec.Basic.Deliver The pika delivery method (e.g., ACK)
    @param properties: pika.spec.BasicProperties Pika properties
    @param body: bytes The received message
    """
    msg = __decode(body, SnapshotEnvelopeDecoder)
    if msg:
        __provision("threatbus/snapshotenvelope", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


@retry(delay=5)
def consume_rabbitmq(conn_params, join_symbol, queue_params):
    """
    Connects to RabbitMQ on the given host/port endpoint. Registers callbacks to
    consumes all messages and initiates further provisioning.
    @param conn_params Pika.ConnectionParameters to connect to RabbitMQ
    @param join_symbol The symbol to use when determining queue and exchange names
    @param queue_params Confuse view of parameters to use for declaring queues
    """
    global logger
    logger.debug("Connecting RabbitMQ consumer...")
    # RabbitMQ connection
    connection = pika.BlockingConnection(conn_params)
    channel = connection.channel()

    # create names and parameters
    exchange_intel = get_exchange_name(join_symbol, "intel")
    exchange_sighting = get_exchange_name(join_symbol, "sighting")
    exchange_snapshotrequest = get_exchange_name(join_symbol, "snapshotrequest")
    exchange_snapshotenvelope = get_exchange_name(join_symbol, "snapshotenvelope")
    queue_name_suffix = queue_params["name_suffix"].get()
    queue_name_suffix = queue_name_suffix if queue_name_suffix else gethostname()
    intel_queue = get_queue_name(join_symbol, "intel", queue_name_suffix)
    sighting_queue = get_queue_name(join_symbol, "sighting", queue_name_suffix)
    snapshot_request_queue = get_queue_name(
        join_symbol, "snapshotrequest", queue_name_suffix
    )
    snapshot_envelope_queue = get_queue_name(
        join_symbol, "snapshotenvelope", queue_name_suffix
    )
    queue_mode = "default" if not queue_params["lazy"].get(bool) else "lazy"
    queue_kwargs = {
        "durable": queue_params["durable"].get(bool),
        "exclusive": queue_params["exclusive"].get(bool),
        "auto_delete": queue_params["auto_delete"].get(bool),
        "arguments": {"x-queue-mode": queue_mode},
    }
    max_items = queue_params["max_items"].get()
    if max_items:
        queue_kwargs["arguments"]["x-max-length"] = max_items

    # bind callbacks to RabbitMQ
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.queue_declare(intel_queue, **queue_kwargs)
    channel.queue_bind(exchange=exchange_intel, queue=intel_queue)
    channel.basic_consume(intel_queue, __provision_intel)

    channel.exchange_declare(exchange=exchange_sighting, exchange_type="fanout")
    channel.queue_declare(sighting_queue, **queue_kwargs)
    channel.queue_bind(exchange=exchange_sighting, queue=sighting_queue)
    channel.basic_consume(sighting_queue, __provision_sighting)

    channel.exchange_declare(exchange=exchange_snapshotrequest, exchange_type="fanout")
    channel.queue_declare(snapshot_request_queue, **queue_kwargs)
    channel.queue_bind(exchange=exchange_snapshotrequest, queue=snapshot_request_queue)
    channel.basic_consume(snapshot_request_queue, __provision_snapshot_request)

    channel.exchange_declare(exchange=exchange_snapshotenvelope, exchange_type="fanout")
    channel.queue_declare(snapshot_envelope_queue, **queue_kwargs)
    channel.queue_bind(
        exchange=exchange_snapshotenvelope, queue=snapshot_envelope_queue
    )
    channel.basic_consume(snapshot_envelope_queue, __provision_snapshot_envelope)

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
        connection.close()
    except Exception as e:
        logger.error(f"Consumer lost connection to RabbitMQ: {e}")
        raise e  # let @retry handle the reconnect


@retry(delay=5)
def publish_rabbitmq(conn_params, join_symbol, inq):
    """
    Connects to RabbitMQ on the given host/port endpoint. Forwards all messages
    from the `inq`, based on their type, to the appropriate RabbitMQ exchange.
    @param conn_params Pika.ConnectionParameters to connect to RabbitMQ
    @param join_symbol The symbol to use when determining queue and exchange names
    @param inq A Queue object to read messages from and publish them to RabbitMQ
    """
    global logger
    logger.debug("Connecting RabbitMQ publisher...")
    connection = pika.BlockingConnection(conn_params)

    # create names and parameters
    exchange_intel = get_exchange_name(join_symbol, "intel")
    exchange_sighting = get_exchange_name(join_symbol, "sighting")
    exchange_snapshotrequest = get_exchange_name(join_symbol, "snapshotrequest")
    exchange_snapshotenvelope = get_exchange_name(join_symbol, "snapshotenvelope")
    channel = connection.channel()
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.exchange_declare(exchange=exchange_sighting, exchange_type="fanout")
    channel.exchange_declare(exchange=exchange_snapshotrequest, exchange_type="fanout")
    channel.exchange_declare(exchange=exchange_snapshotenvelope, exchange_type="fanout")

    # forward messages to RabbitMQ
    while True:
        msg = inq.get(block=True)
        exchange = None
        encoded = None
        try:
            if type(msg) == Intel:
                exchange = exchange_intel
                encoded = json.dumps(msg, cls=IntelEncoder)
            elif type(msg) == Sighting:
                exchange = exchange_sighting
                encoded = json.dumps(msg, cls=SightingEncoder)
            elif type(msg) == SnapshotRequest:
                exchange = exchange_snapshotrequest
                encoded = json.dumps(msg, cls=SnapshotRequestEncoder)
            elif type(msg) == SnapshotEnvelope:
                exchange = exchange_snapshotenvelope
                encoded = json.dumps(msg, cls=SnapshotEnvelopeEncoder)
        except Exception as e:
            logger.warn(f"Discarding unparsable message {msg}: {e}")
            continue
        try:
            channel.basic_publish(exchange=exchange, routing_key="", body=encoded)
            logger.debug(f"Forwarded message to RabbitMQ: {msg}")
            inq.task_done()
        except KeyboardInterrupt:
            connection.close()
            break
        except Exception as e:
            # push back message
            logger.error(f"Failed to send, pushing back message: {msg}")
            logger.error(f"Publisher lost connection to RabbitMQ: {e}")
            if msg:
                inq.put(msg)
                raise e  # let @retry handle the reconnect


@threatbus.backbone
def subscribe(topic, q):
    """
    Threat Bus' subscribe hook. Used to register new app-queues for certain
    topics.
    """
    global subscriptions, lock
    lock.acquire()
    subscriptions[topic].add(q)
    lock.release()


@threatbus.backbone
def unsubscribe(topic, q):
    """
    Threat Bus' unsubscribe hook. Used to deregister app-queues from certain
    topics.
    """
    global subscriptions, lock
    lock.acquire()
    if q in subscriptions[topic]:
        subscriptions[topic].remove(q)
    lock.release()


@threatbus.backbone
def run(config, logging, inq):
    global logger
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))
    host = config["host"].get(str)
    port = config["port"].get(int)
    username = config["username"].get(str)
    password = config["password"].get(str)
    vhost = config["vhost"].get(str)
    credentials = pika.PlainCredentials(username, password)
    conn_params = pika.ConnectionParameters(host, port, vhost, credentials)
    name_pattern = config["naming_join_pattern"].get(str)
    threading.Thread(
        target=consume_rabbitmq,
        args=(conn_params, name_pattern, config["queue"]),
        daemon=True,
    ).start()
    threading.Thread(
        target=publish_rabbitmq,
        args=(conn_params, name_pattern, inq),
        daemon=True,
    ).start()
    logger.info("RabbitMQ backbone started.")
