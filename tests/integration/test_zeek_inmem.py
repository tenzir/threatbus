import broker
from dynaconf.utils.boxing import DynaBox
from datetime import datetime, timedelta, timezone
from multiprocessing import JoinableQueue
from stix2 import Indicator, Sighting
from threading import Thread
from threatbus_zeek import plugin
import time
import unittest
from unittest.mock import ANY, MagicMock
from tests.utils import zeek_receiver, zeek_sender
from queue import Queue


class TestPluginInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = "127.0.0.1"
        cls.port = 47761
        # setup the zeek plugin
        config = DynaBox(
            {
                "zeek": {
                    "host": cls.host,
                    "port": cls.port,
                    "module_namespace": "Tenzir",
                },
                "console": False,
                "file": False,
            }
        )

        cls.inq = JoinableQueue()
        cls.subscribe_callback = MagicMock()
        cls.unsubscribe_callback = MagicMock()
        plugin.run(
            config, config, cls.inq, cls.subscribe_callback, cls.unsubscribe_callback
        )

        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        plugin.stop()
        time.sleep(0.3)

    def setUp(self):
        # self.timestamp = datetime.now(timezone.utc).astimezone()
        self.raw_ts = 1579104545
        self.timestamp = datetime.fromtimestamp(self.raw_ts).astimezone(timezone.utc)
        self.ioc_id = "indicator--42d31a5b-2da0-4bdd-9823-1723a98fc2fb"
        self.ioc_value = "example.com"
        self.ioc = Indicator(
            id=self.ioc_id,
            created=self.timestamp,
            pattern_type="stix",
            pattern=f"[domain-name:value = '{self.ioc_value}']",
        )
        self.ep = broker.Endpoint()
        self.ep.peer(self.host, self.port)
        self.subscribe_callback.reset_mock()
        self.unsubscribe_callback.reset_mock()

    def test_zeek_subscription(self):
        """
        Subscribes via the Zeek plugin's management interface and verfies that
        the Threat Bus `subscribe_callback` is invoked with correct parameters
        """
        topic = "SUBSCRIBE"
        time_delta = timedelta(days=5)
        p2p_topic = zeek_receiver.subscribe(self.ep, topic, time_delta)
        self.subscribe_callback.assert_called_with(topic, ANY, time_delta)
        self.assertTrue(p2p_topic.startswith(topic))

    def test_zeek_unsubscription(self):
        """
        Unubscribes via the Zeek plugin's management interface and verfies that
        the Threat Bus `unsubscribe_callback` is invoked with correct parameters
        """
        ## unsubscribe without subscription
        topic = "UNSUBSCRIBE_FAILURE"
        zeek_receiver.unsubscribe(self.ep, topic)
        self.unsubscribe_callback.assert_not_called()

        ## subscribe, then issue valid unsubscription
        topic = "UNSUBSCRIBE_SUCCESS"
        time_delta = timedelta(days=5)
        p2p_topic = zeek_receiver.subscribe(self.ep, topic, time_delta)
        self.subscribe_callback.assert_called_with(topic, ANY, time_delta)
        self.assertTrue(p2p_topic.startswith(topic))
        zeek_receiver.unsubscribe(self.ep, p2p_topic)
        time.sleep(0.1)
        self.unsubscribe_callback.assert_called_with(topic, ANY)

    def test_zeek_send_sighting(self):
        """
        Send a handful of sightings via Broker to the Zeek plugin's interface
        and verfies that the same amount of correctly mapped STIX-2 sighting is
        forwarded to Threat Bus.
        """
        topic = "stix2/sighting"
        items = 17

        # mock a real Zeek instance and send sightings via Broker
        zeek_sender.send_generic(topic, items)

        # verify that the plugin's
        self.assertEqual(self.inq.qsize(), items)
        for _ in range(items):
            item = self.inq.get()
            self.assertTrue(type(item) is Sighting)
            self.inq.task_done()

    def test_receive_iocs(self):
        """
        Subscribes via the Zeek plugin, then makes the Zeek plugin publish a
        bunch of IoCs and verifies they arrive at the subscriber as valid Broker
        events.
        """
        topic = "stix2/indicator"
        items = 13
        result_q = Queue()
        # install receiver (mocks a real Zeek instance)
        # emulate a zeek subscriber for intel items
        rec = Thread(
            target=zeek_receiver.forward,
            args=(items, result_q, topic),
            daemon=False,
        )
        rec.start()
        time.sleep(0.3)

        self.subscribe_callback.assert_called_with(topic, ANY, ANY)
        called_with = self.subscribe_callback.call_args
        subscriber_queue = called_with.args[1]  # mocked with ANY in the assert
        # push indicators into the subscriber queue, test that they are mapped
        # to Broker events and forwarded on the subscriber's p2p_topic
        for _ in range(items):
            subscriber_queue.put(self.ioc)
        time.sleep(1.5)

        # the zeek_receiver test utils should have received these from the
        # plugin where it is subscribed and forward them to our result_q
        self.assertEqual(result_q.qsize(), items)
        for _ in range(items):
            item = result_q.get()
            self.assertTrue(type(item) is broker.zeek.Event)
            self.assertEqual(item.name(), "Tenzir::intel")
            self.assertEqual(
                item.args()[0],
                (self.timestamp, self.ioc_id, "DOMAIN", self.ioc_value, "ADD"),
            )
            result_q.task_done()
        result_q.join()
        rec.join()
