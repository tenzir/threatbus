## The MISP plugin lists two optional dependencies via `extras_requires`, so
## users can either install `threatbus-misp[zmq]` or `threatbus-misp[kafka]`.
## The plugin needs at least one of these to work properly, so we we need to log
## an error if none of these is installed.
dep_kafka = False
dep_zmq = False
try:
    from confluent_kafka import Consumer

    dep_kafka = True
except ModuleNotFoundError:
    pass
from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from datetime import datetime
from itertools import product
import json
from multiprocessing import JoinableQueue
import pymisp
from queue import Empty
import threading
import threatbus
from threatbus.data import MessageType, SnapshotEnvelope, SnapshotRequest
from threatbus_misp.message_mapping import (
    attribute_to_stix2_indicator,
    stix2_sighting_to_misp,
    is_whitelisted,
)
from typing import Callable, List, Dict
import warnings

try:
    import zmq

    dep_zmq = True
except ModuleNotFoundError:
    pass


warnings.simplefilter("ignore")  # pymisp produces urllib warnings

"""MISP application plugin for Threat Bus"""


plugin_name: str = "misp"
misp: pymisp.api.PyMISP = None
lock: threading.Lock = threading.Lock()
# filter_config is required for message mapping, but not available when Threat Bus invokes `snapshot()` -> global, initialized on startup
filter_config: List[Dict] = None
workers: List[threatbus.StoppableWorker] = list()


class SightingsPublisher(threatbus.StoppableWorker):
    """
    Reports / publishes true-positive sightings of intelligence items back to the given MISP endpoint.
    """

    def __init__(self, outq: JoinableQueue):
        """
        @param outq The queue from which to forward messages to MISP
        """
        super(SightingsPublisher, self).__init__()
        self.outq = outq

    def run(self):
        global logger, misp, lock
        if not misp:
            return
        while self._running():
            try:
                sighting = self.outq.get(block=True, timeout=1)
            except Empty:
                continue
            misp_sighting = stix2_sighting_to_misp(sighting)
            lock.acquire()
            resp = misp.add_sighting(misp_sighting)
            if not resp or type(resp) is dict and resp.get("message", None):
                logger.error(
                    f"Failed to add sighting to MISP: '{sighting}' Error: {resp}"
                )
            else:
                logger.debug(f"Reported sighting: {resp}")
            lock.release()
            self.outq.task_done()


class KafkaReceiver(threatbus.StoppableWorker):
    """
    Binds a Kafka consumer to the the given host/port. Forwards all received messages to the inq.
    """

    def __init__(self, kafka_config: DynaBox, inq: JoinableQueue):
        """
        @param kafka_config A configuration object for Kafka binding
        @param inq The queue to which STIX-2 indicators are forwarded to
        """
        super(KafkaReceiver, self).__init__()
        self.kafka_config = kafka_config
        self.inq = inq

    def run(self):
        consumer = Consumer(self.kafka_config.config)
        consumer.subscribe(self.kafka_config.topics)
        global logger, filter_config
        while self._running():
            message = consumer.poll(timeout=self.kafka_config.poll_interval)
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
            if not is_whitelisted(msg, filter_config):
                continue
            ioc = None
            attr = msg.get("Attribute", None)
            try:
                ioc = attribute_to_stix2_indicator(
                    attr, msg.get("action", None), logger
                )
            except Exception as e:
                logger.warn(f"Failed to parse MISP attribute {attr}: {e}")
            if not ioc:
                # the mapping function returns None e.g., in case a new MISP
                # attribute is added without the `to_ids` flag enabled.
                continue
            self.inq.put(ioc)


class ZmqReceiver(threatbus.StoppableWorker):
    """
    Binds a ZMQ poller to the the given host/port. Forwards all received messages to the inq.
    """

    def __init__(self, zmq_config: DynaBox, inq: JoinableQueue):
        """
        @param zmq_config A configuration object for ZeroMQ binding
        @param inq The queue to which STIX-2 Indicators are forwarded to
        """
        super(ZmqReceiver, self).__init__()
        self.inq = inq
        self.zmq_config = zmq_config

    def run(self):
        global logger, filter_config
        socket = zmq.Context().socket(zmq.SUB)
        socket.connect(f"tcp://{self.zmq_config.host}:{self.zmq_config.port}")
        # TODO: allow reception of more topics, i.e. handle events.
        socket.setsockopt(zmq.SUBSCRIBE, b"misp_json_attribute")
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        while self._running():
            socks = dict(poller.poll(timeout=1000))
            if socket not in socks or socks[socket] != zmq.POLLIN:
                continue
            raw = socket.recv()
            _, message = raw.decode("utf-8").split(" ", 1)
            try:
                msg = json.loads(message)
            except Exception as e:
                logger.error(f"Error decoding message {message}: {e}")
                continue
            if not is_whitelisted(msg, filter_config):
                continue
            ioc = None
            attr = msg.get("Attribute", None)
            try:
                ioc = attribute_to_stix2_indicator(
                    attr, msg.get("action", None), logger
                )
            except Exception as e:
                logger.warn(f"Failed to parse MISP attribute {attr}: {e}")
            if not ioc:
                # the mapping function returns None e.g., in case a new MISP
                # attribute is added without the `to_ids` flag enabled.
                continue
            self.inq.put(ioc)


@threatbus.app
def config_validators() -> List[Validator]:
    ## The MISP plugin is installed with an optional dependency (either `zmq` or
    ## `kafka`). Configuring one of these sections requires to have installed
    ## the correct plugin package.
    zmq_validator = Validator(
        f"plugins.apps.{plugin_name}.zmq",
        condition=lambda value: dep_zmq,
        is_type_of=dict,
        messages={
            "condition": "MISP attribute export is configured via ZeroMQ (setting {name}), but the dependency is not installed. Install `threatbus-misp[zmq]` to use this setting."
        },
    )
    kafka_validator = Validator(
        f"plugins.apps.{plugin_name}.kafka",
        condition=lambda value: dep_kafka,
        is_type_of=dict,
        messages={
            "condition": "MISP attribute export is configured via Apache Kafka (setting {name}), but the dependency is not installed. Install `threatbus-misp[kafka]` to use this setting."
        },
    )
    ## Using `kafka` or `zmq` is mutually exclusive, otherwise this plugin would
    ## receive every indicator update twice. Configuring both sections in the
    ## config file must be prohibited.
    zmq_kafka_mut_exclusive_validator = Validator(
        f"plugins.apps.{plugin_name}.zmq",
        required=True,
        ne=None,
        when=Validator(f"plugins.apps.{plugin_name}.kafka", eq=None),
        messages={
            "operations": "Either configure the MISP plugin to use ZeroMQ or Kafka, but not both."
        },
    ) & Validator(
        f"plugins.apps.{plugin_name}.zmq",
        eq=None,
        when=Validator(f"plugins.apps.{plugin_name}.kafka", required=True, ne=None),
        messages={
            "operations": "Either configure the MISP plugin to use ZeroMQ or Kafka, but not both."
        },
    )
    return [
        Validator(
            f"plugins.apps.{plugin_name}.filter",
            is_type_of=list,
            default=[],
        ),
        # TODO: Allow default values for 'host' and 'ssl'.
        Validator(
            f"plugins.apps.{plugin_name}.api.host",
            f"plugins.apps.{plugin_name}.api.ssl",
            f"plugins.apps.{plugin_name}.api.key",
            when=Validator(f"plugins.apps.{plugin_name}.api", must_exist=True),
            required=True,
            messages={
                "must_exist_true": "All of 'api.host', 'api.ssl', and 'api.key' must be defined when the 'api' key exists"
            },
        ),
        zmq_kafka_mut_exclusive_validator,
        zmq_validator,
        Validator(
            f"plugins.apps.{plugin_name}.zmq.host",
            required=True,
            when=Validator(f"plugins.apps.{plugin_name}.kafka", eq=None),
        ),
        Validator(
            f"plugins.apps.{plugin_name}.zmq.port",
            is_type_of=int,
            required=True,
            when=Validator(f"plugins.apps.{plugin_name}.kafka", eq=None),
        ),
        kafka_validator,
        Validator(
            f"plugins.apps.{plugin_name}.kafka.topics",
            is_type_of=list,
            must_exist=True,
            when=Validator(f"plugins.apps.{plugin_name}.zmq", eq=None),
        ),
        Validator(
            f"plugins.apps.{plugin_name}.kafka.poll_interval",
            is_type_of=float,
            default=1.0,
            when=Validator(f"plugins.apps.{plugin_name}.zmq", eq=None),
        ),
        Validator(
            f"plugins.apps.{plugin_name}.kafka.config",
            is_type_of=dict,
            must_exist=True,
            when=Validator(f"plugins.apps.{plugin_name}.zmq", eq=None),
        ),
    ]


@threatbus.app
def snapshot(snapshot_request: SnapshotRequest, result_q: JoinableQueue):
    global logger, misp, lock, filter_config
    if snapshot_request.snapshot_type != MessageType.INDICATOR:
        logger.debug("Sighting snapshot feature not yet implemented.")
        return  # TODO sighting snapshot not yet implemented
    if not misp:
        logger.debug("Cannot perform snapshot request. No MISP API connection.")
        return

    logger.info(f"Executing intel snapshot for time delta {snapshot_request.snapshot}")
    if not filter_config:
        filter_config = [{}]  # this empty whitelist results in a global query

    # build queries for everything that is whitelisted
    for fil in filter_config:
        orgs = fil.get("orgs", [None])
        types = fil.get("types", [None])
        tags_query = misp.build_complex_query(or_parameters=fil.get("tags", []))
        if not tags_query:
            tags_query = None  # explicit None value

        # By API design, orgs and types must be queried value-by-value
        # None-values mean that all values are accepted
        # https://pymisp.readthedocs.io/en/latest/_modules/pymisp/api.html#PyMISP.search
        for (org, type_) in product(orgs, types):
            lock.acquire()
            data = misp.search(
                org=org,
                type_attribute=type_,
                tags=tags_query,
                controller="attributes",
                to_ids=True,
                date_from=datetime.now() - snapshot_request.snapshot,
            )
            lock.release()
            if not data:
                continue
            for attr in data["Attribute"]:
                try:
                    ioc = attribute_to_stix2_indicator(attr, "add", logger)
                except Exception as e:
                    logger.warn(f"Failed to parse MISP attribute {attr}: {e}")
                if ioc:
                    result_q.put(
                        SnapshotEnvelope(
                            snapshot_request.snapshot_type,
                            snapshot_request.snapshot_id,
                            ioc,
                        )
                    )


@threatbus.app
def run(
    config: DynaBox,
    logging: DynaBox,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, filter_config, workers
    logger = threatbus.logger.setup(logging, __name__)
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    config = config[plugin_name]

    filter_config = config.filter if "filter" in config else {}

    # start Attribute-update receiver
    if "zmq" in config:
        workers.append(ZmqReceiver(config.zmq, inq))
    elif "kafka" in config:
        workers.append(KafkaReceiver(config.kafka, inq))

    # bind to MISP
    if "api" in config:
        # TODO: MISP instances shall subscribe themselves to threatbus and each
        # subscription shall have an individual outq and receiving thread for intel
        # updates.
        try:
            global misp, lock
            lock.acquire()
            misp = pymisp.ExpandedPyMISP(
                url=config.api.host, key=config.api.key, ssl=config.api.ssl
            )
            lock.release()
        except Exception:
            # TODO: log individual error per MISP subscriber
            logger.error(
                f"Cannot subscribe to MISP at {config.api.host}, using SSL: {config.api.ssl}"
            )
            lock.release()
        if not misp:
            logger.error("Failed to start MISP plugin")
            return
    else:
        logger.warning(
            "Starting MISP plugin without API connection, cannot report back sightings or request snapshots."
        )

    outq = JoinableQueue()
    subscribe_callback("stix2/sighting", outq)
    workers.append(SightingsPublisher(outq))
    for w in workers:
        w.start()
    logger.info("MISP plugin started")


@threatbus.app
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("MISP plugin stopped")
