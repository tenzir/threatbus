from cifsdk.client.http import HTTP as Client
from confuse import Subview
from multiprocessing import JoinableQueue
from queue import Empty
import threatbus
from threatbus_cif3.message_mapping import map_to_cif
from typing import Callable, List


"""Threatbus - Open Source Threat Intelligence Platform - plugin for CIFv3"""

plugin_name = "cif3"
workers: List[threatbus.StoppableWorker] = list()


class CIFPublisher(threatbus.StoppableWorker):
    """
    Reports / publishes intel items back to the given CIF endpoint.
    """

    def __init__(self, intel_outq: JoinableQueue, cif: Client, config: Subview):
        """
        @param intel_outq Publish all intel from this queue to CIF
        @param cif The CIF client to use
        @config the plugin config
        """
        super(CIFPublisher, self).__init__()
        self.intel_outq = intel_outq
        self.cif = cif
        self.config = config

    def run(self):
        global logger
        if not self.cif:
            logger.error("CIF is not properly configured. Exiting.")
            return
        confidence = self.config["confidence"].as_number()
        if not confidence:
            confidence = 5
        tags = self.config["tags"].get(list)
        tlp = self.config["tlp"].get(str)
        group = self.config["group"].get(str)

        while self._running():
            try:
                intel = self.intel_outq.get(block=True, timeout=1)
            except Empty:
                continue
            if not intel:
                logger.warning("Received unparsable intel item")
                self.intel_outq.task_done()
                continue
            cif_mapped_intel = map_to_cif(intel, logger, confidence, tags, tlp, group)
            if not cif_mapped_intel:
                self.intel_outq.task_done()
                continue
            try:
                logger.debug(f"Adding intel to CIF: {cif_mapped_intel}")
                self.cif.indicators_create(cif_mapped_intel)
            except Exception as err:
                logger.error(f"CIF submission error: {err}")
            finally:
                self.intel_outq.task_done()


def validate_config(config: Subview):
    assert config, "config must not be None"
    config["tags"].get(list)
    config["tlp"].get(str)
    config["confidence"].as_number()
    config["group"].get(str)
    config["api"].get(dict)
    config["api"]["host"].get(str)
    config["api"]["ssl"].get(bool)
    config["api"]["token"].get(str)


@threatbus.app
def run(
    config: Subview,
    logging: Subview,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    config = config[plugin_name]
    try:
        validate_config(config)
    except Exception as e:
        logger.fatal("Invalid config for plugin {}: {}".format(plugin_name, str(e)))

    remote, token, ssl = (
        config["api"]["host"].get(),
        config["api"]["token"].get(),
        config["api"]["ssl"].get(),
    )
    cif = None
    try:
        cif = Client(remote=remote, token=token, verify_ssl=ssl)
        cif.ping()
    except Exception as err:
        logger.error(
            f"Cannot connect to CIFv3 at {remote}, using SSL: {ssl}. Exiting plugin. {err}"
        )
        return

    intel_outq = JoinableQueue()
    topic = "threatbus/intel"
    subscribe_callback(topic, intel_outq)

    workers.append(CIFPublisher(intel_outq, cif, config))
    for w in workers:
        w.start()

    logger.info("CIF3 plugin started")


@threatbus.app
def stop():
    global logger, workers
    for w in workers:
        if not w.is_alive():
            continue
        w.stop()
        w.join()
    logger.info("CIF3 plugin stopped")
