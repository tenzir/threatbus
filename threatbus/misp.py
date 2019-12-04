import asyncio
import datetime
from enum import Enum, auto
import functools
import json
import logging
import os
import pymisp
import sys
from typing import NamedTuple
import zmq
from zmq.asyncio import Context

PYTHON_3_6 = (3, 6, 6, "final", 0)
PYTHON_3_7 = (3, 7)


def asyncify(f):
    @functools.wraps(f)
    async def coroutine(*args, **kwargs):
        partial = functools.partial(f, *args, **kwargs)
        return await async_loop().run_in_executor(None, partial)

    return coroutine


def async_loop():
    if sys.version_info <= PYTHON_3_6:
        return asyncio.get_event_loop()
    else:
        assert sys.version_info >= PYTHON_3_7
        return asyncio.get_running_loop()


class Action(Enum):
    ADD = auto()
    EDIT = auto()
    REMOVE = auto()


class Intelligence(NamedTuple):
    id: str  # A unique identifier (within the intel source's context).
    type: str  # The type of intelligence.
    value: str  # The value of the item.
    data: str  # The raw data as given by the source
    source: str  # The origin of the intelligence.

    def __repr__(self):
        return f"({self.id}, {self.type}, {self.value}, {self.source})"


def make_action(x):
    attr = x.get("Attribute", None)
    if not attr or attr.get("deleted", None) == 1:
        return Action.REMOVE
    if attr and x.get("Event", None):
        return Action.EDIT
    elif attr:
        return Action.ADD


def make_excerpt(string, max_len=300):
    result = string[:max_len]
    if len(string) > max_len:
        result += "..."
    return result


class MISP:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("threat-bus.misp")
        if config.zmq and config.kafka:
            self.logger.critical("cannot have both 0mq and Kafka configured")
        elif not config.zmq and not config.kafka:
            self.logger.critical("need intel either from Kafka or 0mq")
        if config.zmq:
            zmq_url = f"tcp://{config.zmq.host}:{config.zmq.port}"
            self.logger.info(f"connecting to MISP 0mq socket at {zmq_url}")
            context = Context.instance()
            socket = context.socket(zmq.SUB)
            socket.connect(zmq_url)
            socket.setsockopt(zmq.SUBSCRIBE, b"")

            async def generate():
                try:
                    while True:
                        msg = await socket.recv()
                        topic, _, payload = msg.decode("utf-8").partition(" ")
                        # Filter out heartbeats.
                        if topic == "misp_json_self":
                            uptime = int(json.loads(payload)["uptime"])
                            delta = datetime.timedelta(seconds=uptime)
                            self.logger.debug(
                                "received 0mq keep-alive (uptime "
                                "{:0>8})".format(str(delta))
                            )
                            continue
                        if topic != "misp_json_attribute":
                            continue
                        # Parse the payload.
                        data = json.loads(payload)
                        excerpt = make_excerpt(json.dumps(data))
                        self.logger.debug(f"got attribute via 0mq: {excerpt}")
                        return data
                except:
                    socket.disconnect(zmq_url)
                    raise

            self.generator = generate
        elif config.kafka:
            from confluent_kafka import Consumer, KafkaError

            self.logger.info(
                "subscribing to MISP Kafka at topic " f"{config.kafka.attribute_topic}"
            )
            self.logger.debug(
                "launching Kafka with " f"{json.dumps(config.kafka.config)}"
            )
            consumer = Consumer(config.kafka.config)
            consumer.subscribe([config.kafka.attribute_topic])

            @asyncify
            def generate():
                try:
                    while True:
                        msg = consumer.poll(POLL_INTERVAL)
                        if msg is None:
                            continue
                        if msg.error():
                            if msg.error().code() != KafkaError._PARTITION_EOF:
                                self.logger.error(f"got Kafka error: {msg.error()}")
                            continue
                        data = json.loads(msg.value())
                        excerpt = make_excerpt(json.dumps(data))
                        self.logger.debug(f"got Kafka message: {excerpt}")
                        return data
                except:
                    self.logger.debug("leaving Kafka group and committing offsets")
                    consumer.close()
                    raise

            self.generator = generate
        assert self.generator
        # Connect to MISP instance via API.
        api_key = None
        if "MISP_API_KEY" in os.environ:
            api_key = os.environ["MISP_API_KEY"]
        elif config.rest.api_key:
            api_key = config.rest.api_key
        else:
            self.logger.critical(
                "no MISP API key found: use MISP_API_KEY "
                "environment variable or config file"
            )
        self.logger.info(f"connecting to MISP REST API at {config.rest.url}")
        try:
            self.misp = pymisp.ExpandedPyMISP(
                url=config.rest.url, key=config.rest.api_key, ssl=config.rest.ssl
            )
        except pymisp.PyMISPError:
            self.logger.critical(
                "connection refused while trying to connect " f"to {config.rest.url}"
            )

    async def intel(self):
        """Generates the next intelligence item."""
        while True:
            data = await self.generator()
            return self.process_intel(data)

    def process_intel(self, data):
        assert data
        # https://www.circl.lu/doc/misp/misp-zmq/#misp_json_attribute---attribute-updated-or-created
        attr = data["Attribute"]
        action = make_action(data)
        to_ids = attr.get("to_ids", None)
        if action == Action.ADD and not to_ids:
            self.logger.debug(
                f"ignoring new attribute {attr['id']} " "without IDS flag"
            )
            return
        if action == Action.EDIT and not to_ids:
            self.logger.debug(
                f"translating edit of attribute {attr['id']} "
                "without IDS flag into removal"
            )
            action = Action.REMOVE

        self.logger.debug(f"got {action.name} for intel {attr['id']}")
        return (action, MISP.make_intel_from_attribute(attr))

    async def report(self, id, time_seen):
        """Reports intelligence as (true-positive) sighting."""
        x = pymisp.MISPSighting()
        x.from_dict(id=id, source="VAST", type="0", timestamp=time_seen)
        ts = datetime.datetime.utcfromtimestamp(time_seen)
        self.logger.debug(
            f"reporting intel {id} seen at " f"{ts.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.misp.add_sighting(x)

    def remove_ids_flag(self, attr_id):
        """Removes the IDS flag from noisy attributes."""
        self.misp.update_attribute(attr_id, {"id": attr_id, "to_ids": False})

    def propose_removal_of_ids_flag(self, attr_id):
        """Add a proposal to remove the IDS flag from an attribute."""
        self.logger.debug("proposing to remove IDS flag " f"from attribute {attr_id}")
        self.misp.proposal_edit(attr_id, {"to_ids": False})

    async def snapshot(self):
        data = None
        self.logger.debug(
            "requesting for snapshot with search: "
            f"{json.dumps(self.config.snapshot.search)}"
        )
        if self.config.snapshot.raw:
            return_format = {"returnFormat": "json"}
            params = self.config.snapshot.search
            data = await self.__query({**return_format, **params})
        else:
            data = await self.__search(**self.config.snapshot.search)
        assert data
        return [MISP.make_intel_from_attribute(x) for x in data["Attribute"]]

    @asyncify
    def __search(self, **kwargs):
        """Performs a search over MISP attributes"""
        return self.misp.search(controller="attributes", **kwargs)

    @asyncify
    def __rest_search(self, query):
        """Performs a search over MISP attributes via the internal REST API"""
        return self.misp._PyMISP__query("restSearch", query, controller="attributes")

    @staticmethod
    def make_intel_from_attribute(attr):
        return Intelligence(
            id=attr["id"],
            type=attr["type"],
            value=attr["value"],
            data=attr,
            source="misp",
        )
