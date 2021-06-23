from dynaconf import Dynaconf
import json
from threatbus import start as start_threatbus
import time
import unittest
import zmq


def send_manage_message(endpoint: str, msg: str, timeout: int = 5):
    """
    Helper function to send a 'management' message, following the zmq-app
    protocol.
    @param endpoint A host:port string to connect to via ZeroMQ
    @param msg The message to send as raw String
    @param timeout The period after which the connection attempt is aborted
    """
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(f"tcp://{endpoint}")
    socket.send_string(msg)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    reply = None
    if poller.poll(timeout * 1000):
        reply = socket.recv_json()
    socket.close()
    context.term()
    return reply


class TestMessageRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TestMessageRoundtrip, cls).setUpClass()
        config = Dynaconf(
            settings_file="config_integration_test.yaml",
        )
        cls.threatbus = start_threatbus(config)
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.threatbus.stop()
        time.sleep(1)

    def setUp(self):
        self.endpoint = "localhost:13370"
        self.topic = "TOPIC"
        self.valid_heartbeat = {"action": "heartbeat", "topic": self.topic}
        self.valid_subscription = {"action": "subscribe", "topic": self.topic}
        self.valid_unsubscription = {"action": "unsubscribe", "topic": self.topic}

    def test_zmq_app_management_endpoint_failure(self):
        """
        Sends invalid messages to the management endpoint.
        """
        ## JSON message, but not according to protocol
        invalid_msg = {"action": "FOO"}
        reply = send_manage_message(self.endpoint, json.dumps(invalid_msg))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "unknown request")

        ## no JSON-formatted message
        reply = send_manage_message(self.endpoint, "FOO")
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "error")

    def test_zmq_app_plugin_heartbeat_failure(self):
        """
        Sends heartbeat messages to the management endpoint that lead to errors.
        """
        ## heartbeat without 'topic' field
        invalid_heartbeat = {"action": "heartbeat"}
        reply = send_manage_message(self.endpoint, json.dumps(invalid_heartbeat))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "unknown request")

        ## valid heartbeat, but nobody is subscribed for TOPIC
        reply = send_manage_message(self.endpoint, json.dumps(self.valid_heartbeat))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "error")

    def test_zmq_app_plugin_subscription_failure(self):
        """
        Sends subscription messages to the management endpoint that lead to
        errors.
        """
        ## subscription without 'topic' field
        invalid_subscription = {"action": "subscribe"}
        reply = send_manage_message(self.endpoint, json.dumps(invalid_subscription))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "unknown request")

        ## subscription with malicious 'snapshot' field
        invalid_subscription = {
            "action": "subscribe",
            "topic": self.topic,
            "snapshot": "FOO",
        }
        reply = send_manage_message(self.endpoint, json.dumps(invalid_subscription))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "error")

    def test_zmq_app_plugin_unsubscription_failure(self):
        """
        Sends unsubscription messages to the management endpoint that lead to
        errors.
        """
        ## unsubscription without 'topic' field
        invalid_unsubscription = {"action": "unsubscribe"}
        reply = send_manage_message(self.endpoint, json.dumps(invalid_unsubscription))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "unknown request")

        ## valid unsubscription, but nobody is subscribed for TOPIC
        reply = send_manage_message(
            self.endpoint, json.dumps(self.valid_unsubscription)
        )
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "error")

    def test_zmq_app_plugin_full_roundtrip_success(self):
        """
        Sends a successful subscription, then heartbeat, then unsubscribes via
        the management endpoint.
        """
        reply = send_manage_message(self.endpoint, json.dumps(self.valid_subscription))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "success")
        self.assertIsNotNone(reply["topic"])
        self.assertEquals(reply["pub_endpoint"], "127.0.0.1:13371")
        self.assertEquals(reply["sub_endpoint"], "127.0.0.1:13372")

        p2p_topic = reply["topic"]  # needed for heartbeat and unsubscription
        self.valid_heartbeat["topic"] = p2p_topic
        self.valid_unsubscription["topic"] = p2p_topic

        reply = send_manage_message(self.endpoint, json.dumps(self.valid_heartbeat))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "success")

        reply = send_manage_message(
            self.endpoint, json.dumps(self.valid_unsubscription)
        )
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "success")

        # assert that nobody is subscribed for p2p_topic anymore, so another
        # heartbeat with that topic must error
        reply = send_manage_message(self.endpoint, json.dumps(self.valid_heartbeat))
        self.assertTrue(type(reply) is dict)
        self.assertEquals(reply["status"], "error")
