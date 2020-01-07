#!/usr/bin/python
import broker
import queue
import select
import unittest
import threading

from tests.utils import zeek_receiver, zeek_sender


class TestMessageMapping(unittest.TestCase):
    def test_message_roundtrip(self):
        result_q = queue.Queue()
        items = 5
        rec = threading.Thread(
            target=zeek_receiver.forward, args=(items, result_q), daemon=False
        )
        rec.start()
        zeek_sender.send(items)
        rec.join()

        self.assertEqual(result_q.qsize(), items)
        for _ in range(items):
            topic, event = result_q.get()
            self.assertEqual(topic, "tenzir/threatbus")
            self.assertIsNotNone(event)
            result_q.task_done()
        self.assertEqual(0, result_q.qsize())
        result_q.join()
