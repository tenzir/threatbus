from dynaconf.utils.boxing import DynaBox
from datetime import datetime
from threatbus_misp import plugin as misp_plugin
from threatbus_inmem import plugin as inmem_backbone
from queue import Queue
import time
import unittest
import zmq


class TestRoundtrips(unittest.TestCase):
    def test_misp_plugin_indicator_roundtrip(self):
        """
        Backend agnostic message passing screnario. Sends a single MISP
        Attribute via ZeroMQ to the Threat Bus MISP plugin and checks if the
        sent message is parsed and forwarded correctly as new STIX-2 Indicator.
        """
        timestamp = 1614599635
        misp_attribute_id = "5e1f2787-fcfc-4718-a58a-00b4c0a82f06"
        misp_attribute_indicator = "example.com"
        misp_attribute_type = "domain"
        misp_json_attribute = f"""{{
            "Attribute": {{
                "id": "15",
                "event_id": "1",
                "object_id": "0",
                "object_relation": null,
                "category": "Network activity",
                "type": "{misp_attribute_type}",
                "value1": "{misp_attribute_indicator}",
                "value2": "",
                "to_ids": true,
                "uuid": "{misp_attribute_id}",
                "timestamp": "{timestamp}",
                "distribution": "5",
                "sharing_group_id": "0",
                "comment": "",
                "deleted": false,
                "disable_correlation": false,
                "value": "{misp_attribute_indicator}",
                "Sighting": []
            }},
            "Event": {{
                "id": "1",
                "date": "{timestamp}",
                "info": "adsf",
                "uuid": "5e1ee79d-25c8-42bd-a386-0291c0a82f06",
                "published": false,
                "analysis": "0",
                "threat_level_id": "1",
                "org_id": "1",
                "orgc_id": "1",
                "distribution": "3",
                "sharing_group_id": "0",
                "Orgc": {{
                    "id": "1",
                    "uuid": "5e1edc98-3984-4321-9003-018bfb195b64",
                    "name": "ORGNAME"
                }}
            }},
            "action": "add"
        }}"""

        # emulate a Threat Bus execution environment
        inq = Queue()
        outq = Queue()
        misp_zmq_pub_port = 50001
        socket = zmq.Context().socket(zmq.PUB)
        socket.bind(f"tcp://127.0.0.1:{misp_zmq_pub_port}")

        config = DynaBox(
            {
                "misp": {
                    "zmq": {
                        "host": "127.0.0.1",
                        "port": misp_zmq_pub_port,
                    }
                },
                "inmem": {},
                "console": False,
                "file": False,
            }
        )

        # start MISP plugin and in-memory backbone
        empty_callback = lambda x, y: None
        misp_plugin.run(config, config, inq, empty_callback, empty_callback)
        inmem_backbone.run(config, config, inq)
        inmem_backbone.subscribe("stix2/indicator", outq)
        time.sleep(0.5)

        # send MISP attribute via ZMQ
        socket.send_string(f"misp_json_attribute {misp_json_attribute}")

        # wait for MISP plugin to parse the IoC and forward to backbone where
        # this test's queue is subscribed at
        ioc = outq.get(block=True)
        outq.task_done()
        outq.join()

        self.assertEqual(ioc.created, datetime.fromtimestamp(timestamp))
        self.assertEqual(ioc.id, f"indicator--{misp_attribute_id}")
        self.assertEqual(ioc.pattern_type, "stix")
        self.assertEqual(
            ioc.pattern, f"[domain-name:value = '{misp_attribute_indicator}']"
        )

        # terminate worker threads from plugins
        inmem_backbone.stop()
        misp_plugin.stop()
