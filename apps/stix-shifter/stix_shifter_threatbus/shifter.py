#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import coloredlogs
import confuse
import json
import logging
import signal
from stix2 import parse, Indicator, Bundle
from stix_shifter.stix_translation import stix_translation
from stix_shifter.stix_transmission import stix_transmission
import sys
from threatbus.logger import setup as setup_logging_threatbus
from typing import Union
import warnings
import zmq

# Ignore warnings about SSL configuration in the user configs.
warnings.filterwarnings("ignore")

logger_name = "stix-shifter-threatbus"
logger = logging.getLogger(logger_name)
# List of all running async tasks of the bridge.
async_tasks = []
# The p2p topic sent back by Threat Bus upon successful subscription.
p2p_topic = None
# Boolean flag indicating that the user has issued a SIGNAL (e.g., SIGTERM).
user_exit = False

### --------------------------- Application helpers ---------------------------


def setup_logging_with_level(level: str):
    """
    Sets up a the global logger for console logging with the given loglevel.
    @param level The loglevel to use, e.g., "DEBUG"
    """
    global logger
    log_level = logging.getLevelName(level.upper())

    fmt = "%(asctime)s %(levelname)-8s %(message)s"
    colored_formatter = coloredlogs.ColoredFormatter(fmt)

    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    if logger.level > log_level or logger.level == 0:
        logger.setLevel(log_level)
    handler.setFormatter(colored_formatter)
    logger.addHandler(handler)


def setup_logging_with_config(config: confuse.Subview):
    """
    Sets up the global logger as configured in the `config` object.
    @param config The user-defined logging configuration
    """
    global logger
    logger = setup_logging_threatbus(config, logger_name)
    logging.getLogger("stix-shifter-utils").propagate = False


def validate_config(config: confuse.Subview):
    assert config, "config must not be None"
    config["threatbus"].get(str)
    config["snapshot"].get(int)

    for mod in config["modules"].get(dict):
        config["modules"][mod].get(dict)
        config["modules"][mod]["max_results"].get(int)
        config["modules"][mod]["connection"].get(dict)
        config["modules"][mod]["data_source"].get(dict)
        config["modules"][mod]["data_source"]["type"].get(str)
        config["modules"][mod]["data_source"]["name"].get(str)
        config["modules"][mod]["data_source"]["id"].get(str)
        config["modules"][mod]["transmission"].add({})  # default to empty config
        config["modules"][mod]["translation"].add({})  # default to empty config


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
    Sends a 'management' message, following the threatbus-zmq-app protocol to
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


async def start(zmq_endpoint: str, snapshot: int, modules_config: dict):
    """
    Starts the STIX-Shifter Threat Bus app.
    @param zmq_endpoint The ZMQ management endpoint of Threat Bus ('host:port')
    @param snapshot An integer value to request n days of historical IoC items
    @param modules_config User-provided configuration for STIX-Shifter modules
    """
    global logger, async_tasks, p2p_topic
    # needs to be created inside the same eventloop where it is used
    logger.debug(f"Calling Threat Bus management endpoint {zmq_endpoint}")
    reply = subscribe(zmq_endpoint, "stix2/indicator", snapshot)
    if not reply_is_success(reply):
        logger.error("Subscription failed")
        return
    pub_endpoint = reply.get("pub_endpoint", None)
    sub_endpoint = reply.get("sub_endpoint", None)
    topic = reply.get("topic", None)
    if not pub_endpoint or not sub_endpoint or not topic:
        logger.error("Subscription failed")
        return

    logger.info(f"Subscription successful. New p2p_topic: {topic}")
    if p2p_topic:
        # The 'start' function is called as result of a restart
        # Unsubscribe the old topic as soon as we get a working connection
        logger.info("Cleaning up old p2p_topic subscription ...")
        unsubscribe(zmq_endpoint, p2p_topic)
        atexit.unregister(unsubscribe)
    p2p_topic = topic
    atexit.register(unsubscribe, zmq_endpoint, topic)

    # set task exception handler
    loop = asyncio.get_event_loop()

    def exception_handler(loop, context):
        logger.error(f"Error in async task: {context}")

    loop.set_exception_handler(exception_handler)

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
        asyncio.create_task(process_indicators(indicator_queue, modules_config))
    )

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


async def process_indicators(indicator_queue: asyncio.Queue, modules_config: dict):
    """
    Translates STIX-2 pattern and queries all configured modules via
    STIX-Shifter.
    @param indicator_queue The queue to put arriving IoCs into
    @param modules_config User-provided configuration for STIX-Shifter modules
    """
    while True:
        msg = await indicator_queue.get()
        try:
            indicator = parse(msg, allow_custom=True)
        except Exception as e:
            logger.error(
                f"Error parsing indicator from Threat Bus. Expected STIX-2 Indicator: {msg}, {e}"
            )
            indicator_queue.task_done()
            continue
        logger.debug(
            f"Converting indicator from Threat Bus to module-specific query: {indicator}"
        )
        for module, opts in modules_config.items():
            asyncio.create_task(query_indicator(indicator, module, opts))
        indicator_queue.task_done()


async def query_indicator(indicator: Indicator, module: str, opts: dict):
    """
    Translates an indicator into a module-specific query and executes it. E.g.,
    if the module is `splunk`, the indicator's pattern is first translated into
    a valid Splunk query and then executed via the Splunk REST API.
    @param indicator The indicator to translate and query
    @param module The module's name, e.g., `splunk`
    @param opts The module configuration directly taken from the user-defined
        configuration file `config.yaml` with which this app was started
    """
    max_results = opts["max_results"]
    connection_opts = opts["connection"]
    transmission_opts = opts.get("transmission", {})
    translation_opts = opts.get("translation", {})
    data_source = opts["data_source"]

    ## Translate the pattern to a module-specific query.
    translation = stix_translation.StixTranslation()
    dsl = translation.translate(
        module, "query", indicator, indicator.pattern, translation_opts
    )
    if not dsl.get("queries", None):
        logger.error(
            f"Failed to translate STIX-2 indicator with ID '{indicator.id}' to query for module '{module}': {dsl}"
        )
        return
    logger.debug(f"Translated pattern to {module} query: {dsl}")

    ## Run the query against the configured endpoint for this module.
    transmission = stix_transmission.StixTransmission(
        module, connection_opts, transmission_opts
    )
    query_results = []
    for query in dsl["queries"]:
        search_result = transmission.query(query)
        if not search_result["success"]:
            logger.error(str(search_result))
            continue

        search_id = search_result["search_id"]

        if transmission.is_async():
            status = transmission.status(search_id)
            if not status.get("success", None):
                logger.error(f"Fetching query status failed for module '{module}'")
                return
            while status["progress"] < 100 and status["status"] == "RUNNING":
                status = transmission.status(search_id)
                await asyncio.sleep(0.05)
        result = transmission.results(search_id, 0, max_results)
        if result["success"]:
            # Collect all results
            query_results += result["data"]
        else:
            logger.error(f"Fetching results failed for module '{module}': {result}")

    ## Translate query_results to STIX.
    if not query_results:
        return

    stix_results = translation.translate(
        module,
        "results",
        json.dumps(data_source),
        json.dumps(query_results),
        translation_opts,
    )
    # TODO: parse output and report back sightings
    logger.debug(f"STIX Results: {stix_results}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Path to a configuration file")
    args = parser.parse_args()

    # Note that you must use names without dashes, use underscores instead for
    # `confuse` to work without errors.
    # Confuse uses the configuration name to lookup environment variables, but
    # it simply upper-cases that name. Dashes are not replaced properly. Using a
    # dash in the configuration name makes it impossible to configure the
    # APPNAMEDIR env variable to overwrite search paths, i.e., in systemd
    # https://confit.readthedocs.io/en/latest/#search-paths
    # https://github.com/beetbox/confuse/blob/v1.4.0/confuse/core.py#L555
    config = confuse.Configuration("stix_shifter")
    config.set_args(args)
    if args.config:
        config.set_file(args.config)

    try:
        validate_config(config)
    except Exception as e:
        sys.exit(ValueError(f"Invalid config: {e}"))

    if config["logging"].get(dict):
        setup_logging_with_config(config["logging"])
    else:
        setup_logging_with_level(config["loglevel"].get(str))

    while True:
        try:
            asyncio.run(
                start(
                    config["threatbus"].get(),
                    config["snapshot"].get(),
                    config["modules"].get(dict),
                )
            )
        except (KeyboardInterrupt, SystemExit):
            return
        except asyncio.CancelledError:
            if user_exit:
                # Tasks were cancelled because the user stopped the app.
                return
            logger.info("Restarting stix-shifter-threatbus ...")


if __name__ == "__main__":
    main()
