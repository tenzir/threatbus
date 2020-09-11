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
exchange_intel = "threatbus-intel"
exchange_sightings = "threatbus-sighting"
exchange_snapshot_requests = "threatbus-snapshot-requests"
exchange_snapshot_envelopes = "threatbus-snapshot-envelopes"


def validate_config(config):
    assert config, "config must not be None"
    config["host"].get(str)
    config["port"].get(int)


def provision(topic, msg):
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
        provision("threatbus/intel", msg)
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
        provision("threatbus/sighting", msg)
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
        provision("threatbus/snapshotrequest", msg)
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
        provision("threatbus/snapshotenvelope", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


@retry(delay=5)
def consume_rabbitmq(host, port):
    """
    Connects to RabbitMQ on the given host/port endpoint. Registers callbacks to
    consumes all messages and initiates further provisioning.
    @param host The RabbitMQ hostname or IP address
    @param port The RabbitMQ port
    """
    global logger
    logger.debug("Connecting RabbitMQ consumer...")
    connection = pika.BlockingConnection(pika.ConnectionParameters(host, port))
    channel = connection.channel()

    intel_queue = f"threatbus-intel-{gethostname()}"
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.queue_declare(intel_queue, durable=True, auto_delete=False)
    channel.queue_bind(exchange=exchange_intel, queue=intel_queue)
    channel.basic_consume(intel_queue, __provision_intel)

    sightings_queue = f"threatbus-sightings-{gethostname()}"
    channel.exchange_declare(exchange=exchange_sightings, exchange_type="fanout")
    channel.queue_declare(sightings_queue, durable=True, auto_delete=False)
    channel.queue_bind(exchange=exchange_sightings, queue=sightings_queue)
    channel.basic_consume(sightings_queue, __provision_sighting)

    snapshot_request_queue = f"threatbus-snapshot-requests-{gethostname()}"
    channel.exchange_declare(
        exchange=exchange_snapshot_requests, exchange_type="fanout"
    )
    channel.queue_declare(snapshot_request_queue, durable=True, auto_delete=False)
    channel.queue_bind(
        exchange=exchange_snapshot_requests, queue=snapshot_request_queue
    )
    channel.basic_consume(snapshot_request_queue, __provision_snapshot_request)

    snapshot_envelope_queue = f"threatbus-snapshot-envelopes-{gethostname()}"
    channel.exchange_declare(
        exchange=exchange_snapshot_envelopes, exchange_type="fanout"
    )
    channel.queue_declare(snapshot_envelope_queue, durable=True, auto_delete=False)
    channel.queue_bind(
        exchange=exchange_snapshot_envelopes, queue=snapshot_envelope_queue
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
def publish_rabbitmq(host, port, inq):
    """
    Connects to RabbitMQ on the given host/port endpoint. Fowards all messages
    from the `inq`, based on their type, to the appropriate RabbitMQ exchange.
    @param host The RabbitMQ hostname or IP address
    @param port The RabbitMQ port
    @param inq A Queue object to read messages from and publish them to RabbitMQ
    """
    global logger
    logger.debug("Connecting RabbitMQ publisher...")
    connection = pika.BlockingConnection(pika.ConnectionParameters(host, port))
    channel = connection.channel()
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.exchange_declare(exchange=exchange_sightings, exchange_type="fanout")
    channel.exchange_declare(
        exchange=exchange_snapshot_requests, exchange_type="fanout"
    )
    channel.exchange_declare(
        exchange=exchange_snapshot_envelopes, exchange_type="fanout"
    )
    while True:
        msg = inq.get(block=True)
        exchange = None
        encoded = None
        try:
            if type(msg) == Intel:
                exchange = exchange_intel
                encoded = json.dumps(msg, cls=IntelEncoder)
            elif type(msg) == Sighting:
                exchange = exchange_sightings
                encoded = json.dumps(msg, cls=SightingEncoder)
            elif type(msg) == SnapshotRequest:
                exchange = exchange_snapshot_requests
                encoded = json.dumps(msg, cls=SnapshotRequestEncoder)
            elif type(msg) == SnapshotEnvelope:
                exchange = exchange_snapshot_envelopes
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
    threading.Thread(target=consume_rabbitmq, args=(host, port), daemon=True).start()
    threading.Thread(
        target=publish_rabbitmq, args=(host, port, inq), daemon=True
    ).start()
    logger.info("RabbitMQ backbone started.")
