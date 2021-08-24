#!/usr/bin/env python3

import argparse
import asyncio
import atexit
from dynaconf import Dynaconf, Validator
from dynaconf.base import Settings
from dynaconf.utils.boxing import DynaBox
from datetime import datetime
import logging
from os.path import dirname, join
from parsuricata import parse_rules
import re
from shlex import split as lexical_split
from shutil import move
import signal
from stix2 import parse
import sys
from threatbus.data import Operation, ThreatBusSTIX2Constants
from threatbus.logger import setup as setup_logging_threatbus
import zmq

logger_name = "suricata-threatbus"
logger = logging.getLogger(logger_name)
# List of all running async tasks of the bridge.
async_tasks = []
# The p2p topic sent back by Threat Bus upon successful subscription.
p2p_topic = None
# Boolean flag indicating that the user has issued a SIGNAL (e.g., SIGTERM).
user_exit = False
# Timestamp of the last write to the rule file maintained by this app.
last_rule_file_update: datetime = datetime.now()
# Timestamp of the last time Suricata was instructed to reload its rulesets.
last_rule_ingest: datetime = datetime.now()

### --------------------------- Application helpers ---------------------------


def setup_logging_with_config(config: DynaBox):
    """
    Sets up the global logger as configured in the `config` object.
    @param config The user-defined logging configuration
    """
    global logger
    logger = setup_logging_threatbus(config, logger_name)


def validate_config(config: Settings):
    """
    Validates the given Dynaconf object. Throws if the config is invalid.
    """
    validators = [
        Validator("logging.console", is_type_of=bool, default=True),
        Validator("logging.file", is_type_of=bool, default=False),
        Validator(
            "logging.console_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
        ),
        Validator(
            "logging.file_verbosity",
            is_in=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
        ),
        Validator("logging.filename", default="suricata-threatbus.log"),
        Validator("threatbus", default="localhost:13370"),
        Validator("socket", "rules_file", required=True),
        Validator("snapshot", is_type_of=int, default=30),
        Validator("reload_interval", is_type_of=int, default=60),
    ]

    config.validators.register(*validators)
    config.validators.validate()


async def cancel_async_tasks():
    """
    Cancels all async tasks.
    """
    global async_tasks
    for task in async_tasks:
        if task is not asyncio.current_task():
            task.cancel()
            del task
    async_tasks = []
    return await asyncio.gather(*async_tasks)


async def stop_signal():
    """
    Implements Python's asyncio eventloop signal handler
    https://docs.python.org/3/library/asyncio-eventloop.html
    Cancels all running tasks and exits the app.
    """
    global user_exit
    user_exit = True
    await cancel_async_tasks()


### --------------- ZeroMQ communication / management functions ---------------


def send_manage_message(endpoint: str, action: dict, timeout: int = 5):
    """
    Sends a 'management' message, following the threatbus-zmq protocol to
    either subscribe or unsubscribe this application to/from Threat Bus.
    @param endpoint A host:port string to connect to via ZeroMQ
    @param action The message to send as JSON
    @param timeout The period after which the connection attempt is aborted
    """
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_json(action)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = None
    if poller.poll(timeout * 1000):
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


def reply_is_success(reply: dict):
    """
    Predicate to check if `reply` is a dict and contains the key-value pair
    "status" = "success"
    @param reply A python dict
    @return True if the dict contains "status" = "success"
    """
    return (
        reply
        and type(reply) is dict
        and reply.get("status", None)
        and reply["status"] == "success"
    )


def subscribe(endpoint: str, topic: str, snapshot: int, timeout: int = 5):
    """
    Subscribes this app to Threat Bus for the given topic. Requests an optional
    snapshot of historical indicators.
    @param endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param topic The topic to subscribe to
    @param snapshot An integer value to request n days of historical IoC items
    @param timeout The period after which the connection attempt is aborted
    """
    global logger
    logger.info(f"Subscribing to topic '{topic}'...")
    action = {"action": "subscribe", "topic": topic, "snapshot": snapshot}
    return send_manage_message(endpoint, action, timeout)


def unsubscribe(endpoint: str, topic: str, timeout: int = 5):
    """
    Unsubscribes this app from Threat Bus for the given topic.
    @param endpoint The ZMQ management endpoint of Threat Bus
    @param topic The topic to unsubscribe from
    @param timeout The period after which the connection attempt is aborted
    """
    global logger
    logger.info(f"Unsubscribing from topic '{topic}' ...")
    action = {"action": "unsubscribe", "topic": topic}
    reply = send_manage_message(endpoint, action, timeout)
    if not reply_is_success(reply):
        logger.warning("Unsubscription failed")
        return
    logger.info("Unsubscription successful")


async def heartbeat(endpoint: str, p2p_topic: str, interval: int = 5):
    """
    Sends heartbeats to Threat Bus periodically to check if the given p2p_topic
    is still valid at the Threat Bus host. Cancels all async tasks of this app
    when the heartbeat fails and stops the heartbeat.
    @param endpoint The ZMQ management endpoint of Threat Bus
    @param p2p_topic The topic string to include in the heartbeat
    @param timeout The period after which the connection attempt is aborted
    """
    global logger
    action = {"action": "heartbeat", "topic": p2p_topic}
    while True:
        reply = send_manage_message(endpoint, action, interval)
        if not reply_is_success(reply):
            logger.error("Subscription with Threat Bus host became invalid")
            return await cancel_async_tasks()
        await asyncio.sleep(interval)


### --------------------------- The actual app logic ---------------------------


async def start(
    zmq_endpoint: str, snapshot: int, socket: str, rules_file: str, reload_interval: int
):
    """
    Starts the Suricata app.
    @param zmq_endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param snapshot An integer value to request n days of historical IoC items
    @param socket The Suricata UNIX socket to connect with
    @param rules_file The Threat Bus rules file maintained by this app
    @param reload_interval The periodic interval to reload Threat Bus rules
    """
    global logger, async_tasks, p2p_topic
    # needs to be created inside the same eventloop where it is used
    logger.debug(f"Calling Threat Bus management endpoint {zmq_endpoint}")
    reply = subscribe(zmq_endpoint, "stix2/indicator", snapshot)
    if not reply_is_success(reply):
        logger.error("Subscription failed")
        return
    pub_port = reply.get("pub_port", None)
    sub_port = reply.get("sub_port", None)
    topic = reply.get("topic", None)
    if not pub_port or not sub_port or not topic:
        logger.error("Subscription failed")
        return
    zmq_host = zmq_endpoint.split(":")[0]
    pub_endpoint = f"{zmq_host}:{pub_port}"
    sub_endpoint = f"{zmq_host}:{sub_port}"

    logger.info(f"Subscription successful. New p2p_topic: {topic}")
    if p2p_topic:
        # The 'start' function is called as result of a restart
        # Unsubscribe the old topic as soon as we get a working connection
        logger.info("Cleaning up old p2p_topic subscription ...")
        unsubscribe(zmq_endpoint, p2p_topic)
        atexit.unregister(unsubscribe)
    p2p_topic = topic
    atexit.register(unsubscribe, zmq_endpoint, topic)

    # Start a heartbeat task so we notice when the Threat Bus host goes away
    async_tasks.append(
        asyncio.create_task(heartbeat(zmq_endpoint, p2p_topic, interval=5))
    )

    # Start a receive task to retrieve real-time updates from Threat Bus
    indicator_queue = asyncio.Queue()
    async_tasks.append(
        asyncio.create_task(receive(pub_endpoint, p2p_topic, indicator_queue))
    )
    async_tasks.append(
        asyncio.create_task(update_suricata_rules(indicator_queue, rules_file))
    )
    async_tasks.append(asyncio.create_task(reload_rules(socket, reload_interval)))

    loop = asyncio.get_event_loop()
    for s in [signal.SIGHUP, signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(s, lambda: asyncio.create_task(stop_signal()))
    return await asyncio.gather(*async_tasks)


async def receive(pub_endpoint: str, topic: str, indicator_queue: asyncio.Queue):
    """
    Starts a zmq subscriber on the given endpoint and listens for new messages
    that are published on the given topic (zmq prefix matching). Depending on
    the topic suffix, Indicators are enqueued to the indicator_queue.
    @param pub_endpoint A host:port string to connect to via zmq
    @param topic The topic prefix to subscribe to intelligence items
    @param indicator_queue The queue to put arriving IoCs into
    """
    global logger
    socket = zmq.Context().socket(zmq.SUB)
    socket.connect(f"tcp://{pub_endpoint}")
    socket.setsockopt(zmq.SUBSCRIBE, topic.encode())
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    logger.info(f"Receiving via ZMQ on topic {pub_endpoint}/{topic}")
    while True:
        socks = dict(poller.poll(timeout=100))  # Smaller timeouts increase CPU load
        if socket in socks and socks[socket] == zmq.POLLIN:
            try:
                topic, msg = socket.recv().decode().split(" ", 1)
            except Exception as e:
                logger.error(f"Error decoding message: {e}")
                continue
            # The topic is suffixed with the message type. Use it for filtering
            if not topic.endswith("indicator"):
                logger.debug(f"Skipping unsupported message: {msg}")
                continue
            # Put the message into the queue for incoming intel items, so they
            # can be processed asynchronously
            await indicator_queue.put(msg)
        else:
            await asyncio.sleep(0.01)  # Free event loop for other tasks


async def update_suricata_rules(indicator_queue: asyncio.Queue, rules_file: str):
    """
    Updates the Suricata `threatbus.rules` with the received STIX-2 Indicator.
    @param indicator_queue The queue to receive IoCs from
    @param rules_file The file to update with new rules.
    """
    global last_rule_file_update
    while True:
        msg = await indicator_queue.get()
        indicator = parse(msg, allow_custom=True)
        if (
            indicator.pattern_type != "Suricata"
            and indicator.pattern_type != "suricata"
        ):
            # Skip STIX- and other indicator types.
            indicator_queue.task_done()
            continue
        try:
            indicator_rule = parse_rules(indicator.pattern)[0]
            sid = list(filter(lambda o: o.keyword == "sid", indicator_rule.options))[
                0
            ].settings
        except Exception as e:
            logger.error(f"Could not parse Suricata rule from indicator: {e}")
            indicator_queue.task_done()
            continue
        with open(rules_file, "r") as rfile:
            rules = rfile.readlines()
        tmp_file = join(dirname(rules_file), "temp.rules")
        pattern = re.compile(f".*sid:\\s?{sid}")
        with open(tmp_file, "w") as tfile:
            ## Remove already exisintg rules with the same SID to enable update
            ## and removal of rules.
            for rule in rules:
                if re.search(pattern, rule):
                    continue
                tfile.write(rule)
            if (
                ThreatBusSTIX2Constants.X_THREATBUS_UPDATE.value not in indicator
                or indicator.x_threatbus_update != Operation.REMOVE.value
            ):
                # Not a remove operation - append the new Suricata rule.
                new_rule = indicator.pattern
                if not new_rule.endswith("\n"):
                    new_rule += "\n"
                tfile.write(new_rule)
        indicator_queue.task_done()
        move(tmp_file, rules_file)
        last_rule_file_update = datetime.now()
        logger.debug(f"Updated Threat Bus rule file with {indicator.pattern}")


async def reload_rules(socket: str, reload_interval: int):
    """
    Triggers a reload of all Suricata rules via `suricatasc` using the given
    interval.
    @param reload_interval The interval (seconds) in which to trigger a rule
    reload.
    """
    global last_rule_ingest
    while True:
        if last_rule_ingest > last_rule_file_update:
            # Only trigger a re-ingest of Suricata rules if there was an update
            await asyncio.sleep(reload_interval)
            continue
        proc = await asyncio.create_subprocess_exec(
            *lexical_split(f"suricatasc -c ruleset-reload-nonblocking {socket}"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if stderr:
            logger.error(
                f"Error while calling `suricatasc -c ruleset-reload-nonblocking [socket]`: {stderr.decode()}"
            )
        else:
            logger.debug(f"Triggered rule reload. Log output: {stdout.decode()}")
        last_rule_ingest = datetime.now()
        await asyncio.sleep(reload_interval)


def main():
    ## Default list of settings files for Dynaconf to parse.
    settings_files = ["config.yaml", "config.yml"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="path to a configuration file")
    args = parser.parse_args()
    if args.config:
        if not args.config.endswith("yaml") and not args.config.endswith("yml"):
            sys.exit("Please provide a `yaml` or `yml` configuration file.")
        ## Allow users to provide a custom config file that takes precedence.
        settings_files = [args.config]

    config = Dynaconf(
        settings_files=settings_files,
        load_dotenv=True,
        envvar_prefix="SURICATA_THREATBUS",
    )

    try:
        validate_config(config)
    except Exception as e:
        sys.exit(ValueError(f"Invalid config: {e}"))

    setup_logging_with_config(config.logging)

    while True:
        try:
            asyncio.run(
                start(
                    config.threatbus,
                    config.snapshot,
                    config.socket,
                    config.rules_file,
                    config.reload_interval,
                )
            )
        except (KeyboardInterrupt, SystemExit):
            return
        except asyncio.CancelledError:
            if user_exit:
                # Tasks were cancelled because the user stopped the app.
                return
            logger.info("Restarting Suricata app ...")


if __name__ == "__main__":
    main()
