from cifsdk.client.http import HTTP as Client
from dynaconf import Validator
from dynaconf.utils.boxing import DynaBox
from multiprocessing import JoinableQueue
from queue import Empty
import threatbus
from threatbus_cif3.message_mapping import map_to_cif
from typing import Callable, List


"""CIFv3 application plugin for Threat Bus"""

plugin_name = "cif3"
workers: List[threatbus.StoppableWorker] = list()


class CIFPublisher(threatbus.StoppableWorker):
    """
    Reports / publishes Indicators to the given CIF endpoint.
    """

    def __init__(self, indicator_q: JoinableQueue, cif: Client, config: DynaBox):
        """
        @param indicator_q Publish all indicators from this queue to CIF
        @param cif The CIF client to use
        @config the plugin config
        """
        super(CIFPublisher, self).__init__()
        self.indicator_q = indicator_q
        self.cif = cif
        self.config = config

    def run(self):
        global logger
        if not self.cif:
            logger.error("CIF is not properly configured. Exiting.")
            return
        confidence = self.config.confidence
        if not confidence:
            confidence = 5
        tags = self.config.tags
        tlp = self.config.tlp
        group = self.config.group

        while self._running():
            try:
                indicator = self.indicator_q.get(block=True, timeout=1)
            except Empty:
                continue
            if not indicator:
                self.indicator_q.task_done()
                continue
            cif_mapped_intel = map_to_cif(
                indicator, confidence, tags, tlp, group, logger
            )
            if not cif_mapped_intel:
                self.indicator_q.task_done()
                continue
            try:
                logger.debug(f"Adding indicator to CIF {cif_mapped_intel}")
                self.cif.indicators_create(cif_mapped_intel)
            except Exception as err:
                logger.error(f"Error adding indicator to CIF {err}")
            finally:
                self.indicator_q.task_done()


@threatbus.app
def config_validators() -> List[Validator]:
    return [
        Validator(
            f"plugins.apps.{plugin_name}.group",
            default="everyone",
        ),
        Validator(
            f"plugins.apps.{plugin_name}.tlp",
            default="amber",
        ),
        Validator(
            f"plugins.apps.{plugin_name}.confidence",
            is_type_of=float,
            default=7.5,
        ),
        Validator(
            f"plugins.apps.{plugin_name}.tags",
            is_type_of=list,
            required=True,
        ),
        Validator(
            f"plugins.apps.{plugin_name}.api.host",
            f"plugins.apps.{plugin_name}.api.token",
            required=True,
        ),
        Validator(
            f"plugins.apps.{plugin_name}.api.ssl",
            is_type_of=bool,
            required=True,
        ),
    ]


@threatbus.app
def run(
    config: DynaBox,
    logging: DynaBox,
    inq: JoinableQueue,
    subscribe_callback: Callable,
    unsubscribe_callback: Callable,
):
    global logger, workers
    logger = threatbus.logger.setup(logging, __name__)
    assert plugin_name in config, f"Cannot find configuration for {plugin_name} plugin"
    config = config[plugin_name]

    cif = None
    try:
        cif = Client(
            remote=config.api.host, token=config.api.token, verify_ssl=config.api.ssl
        )
        cif.ping()
    except Exception as err:
        logger.error(
            f"Cannot connect to CIFv3 at {config.api.host}, using SSL: {config.api.ssl}. Exiting plugin. {err}"
        )
        return

    indicator_q = JoinableQueue()
    topic = "stix2/indicator"
    subscribe_callback(topic, indicator_q)

    workers.append(CIFPublisher(indicator_q, cif, config))
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
