from collections import defaultdict
import json
import pika
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
    global subscriptions, lock
    logger.debug(f"Relaying message from RabbitMQ: {msg}")
    lock.acquire()
    for t in filter(lambda t: str(topic).startswith(str(t)), subscriptions.keys()):
        for outq in subscriptions[t]:
            outq.put(msg)
    lock.release()


def provision_intel(channel, method_frame, header_frame, body):
    try:
        msg = json.loads(body, cls=IntelDecoder)
    except Exception as e:
        logger.error(f"Error decoding intel message {body}: {e}")
        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
        return
    provision("threatbus/intel", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def provision_sighting(channel, method_frame, header_frame, body):
    try:
        msg = json.loads(body, cls=SightingDecoder)
    except Exception as e:
        logger.error(f"Error decoding sighting message {body}: {e}")
        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
        return
    provision("threatbus/sightings", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def provision_snapshot_request(channel, method_frame, header_frame, body):
    try:
        msg = json.loads(body, cls=SnapshotRequestDecoder)
    except Exception as e:
        logger.error(f"Error decoding SnapshotRequest {body}: {e}")
        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
        return
    provision("threatbus/snapshotrequest", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def provision_snapshot_envelope(channel, method_frame, header_frame, body):
    try:
        msg = json.loads(body, cls=SnapshotEnvelopeDecoder)
    except Exception as e:
        logger.error(f"Error decoding SnapshotEnvelope {body}: {e}")
        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
        return
    provision("threatbus/snapshotenvelope", msg)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)


def consume_rabbitmq(host, port):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host, port))
    channel = connection.channel()

    intel_queue = f"threatbus-intel-{gethostname()}"
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.queue_declare(intel_queue, durable=True, auto_delete=False)
    channel.queue_bind(exchange=exchange_intel, queue=intel_queue)
    channel.basic_consume(intel_queue, provision_intel)

    sightings_queue = f"threatbus-sightings-{gethostname()}"
    channel.exchange_declare(exchange=exchange_sightings, exchange_type="fanout")
    channel.queue_declare(sightings_queue, durable=True, auto_delete=False)
    channel.queue_bind(exchange=exchange_sightings, queue=sightings_queue)
    channel.basic_consume(sightings_queue, provision_sighting)

    snapshot_request_queue = f"threatbus-snapshot-requests-{gethostname()}"
    channel.exchange_declare(
        exchange=exchange_snapshot_requests, exchange_type="fanout"
    )
    channel.queue_declare(snapshot_request_queue, durable=True, auto_delete=False)
    channel.queue_bind(
        exchange=exchange_snapshot_requests, queue=snapshot_request_queue
    )
    channel.basic_consume(snapshot_request_queue, provision_snapshot_request)

    snapshot_envelope_queue = f"threatbus-snapshot-envelopes-{gethostname()}"
    channel.exchange_declare(
        exchange=exchange_snapshot_envelopes, exchange_type="fanout"
    )
    channel.queue_declare(snapshot_envelope_queue, durable=True, auto_delete=False)
    channel.queue_bind(
        exchange=exchange_snapshot_envelopes, queue=snapshot_envelope_queue
    )
    channel.basic_consume(snapshot_envelope_queue, provision_snapshot_envelope)

    try:
        channel.start_consuming()
    except (KeyboardInterrupt, pika.exceptions.ConnectionClosedByBroker):
        channel.stop_consuming()
        connection.close()


def publish_rabbitmq(host, port, inq):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host, port))
    channel = connection.channel()
    channel.exchange_declare(exchange=exchange_intel, exchange_type="fanout")
    channel.exchange_declare(exchange=exchange_sightings, exchange_type="fanout")

    while True:
        msg = inq.get(block=True)
        exchange = None
        encoded = None
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
        if not encoded:
            logger.warn(f"Unable to encode message: {msg}")
            continue
        logger.debug(f"Forwarding message to RabbitMQ: {msg}")
        channel.basic_publish(exchange=exchange, routing_key="", body=encoded)


@threatbus.backbone
def subscribe(topic, q):
    global subscriptions, lock
    lock.acquire()
    subscriptions[topic].add(q)
    lock.release()


@threatbus.backbone
def unsubscribe(topic, q):
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
