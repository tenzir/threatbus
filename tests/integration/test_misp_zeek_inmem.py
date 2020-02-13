import queue
import threading
import unittest

from tests.utils import zmq_sender, zeek_receiver


class TestRoundtrips(unittest.TestCase):
    def test_zeek_plugin_message_roundtrip(self):
        """
            Backend agnostic message passing screnario. Sends a single MISP
            Attribute via ZeroMQ to the threatbus MISP plugin, subscribes via
            broker to threatbus, and checks if the initially sent message got
            parsed and forwarded correctly as new Intelligence item.
        """
        misp_json_attribute = """{
            "Attribute": {
                "id": "15",
                "event_id": "1",
                "object_id": "0",
                "object_relation": null,
                "category": "Network activity",
                "type": "domain",
                "value1": "example.com",
                "value2": "",
                "to_ids": false,
                "uuid": "5e1f2787-fcfc-4718-a58a-00b4c0a82f06",
                "timestamp": "1579104545",
                "distribution": "5",
                "sharing_group_id": "0",
                "comment": "",
                "deleted": false,
                "disable_correlation": false,
                "value": "example.com",
                "Sighting": []
            },
            "Event": {
                "id": "1",
                "date": "2020-01-15",
                "info": "adsf",
                "uuid": "5e1ee79d-25c8-42bd-a386-0291c0a82f06",
                "published": false,
                "analysis": "0",
                "threat_level_id": "1",
                "org_id": "1",
                "orgc_id": "1",
                "distribution": "3",
                "sharing_group_id": "0",
                "Orgc": {
                    "id": "1",
                    "uuid": "5e1edc98-3984-4321-9003-018bfb195b64",
                    "name": "ORGNAME"
                }
            },
            "action": "edit"
        }"""

        # emulate a zeek subscriber for intel items
        result_q = queue.Queue()
        rec = threading.Thread(
            target=zeek_receiver.forward,
            args=(1, result_q, "tenzir/threatbus/intel"),
            daemon=False,
        )
        rec.start()

        zmq_sender.send(misp_json_attribute)

        # wait for threatbus to forward intel
        zeek_intel = result_q.get(block=True)
        result_q.task_done()
        result_q.join()
        rec.join()

        self.assertEqual(
            zeek_intel,
            [
                (
                    "Tenzir::intel",
                    None,
                    "15",
                    {"indicator": "example.com", "intel_type": "DOMAIN"},
                )
            ],
        )
