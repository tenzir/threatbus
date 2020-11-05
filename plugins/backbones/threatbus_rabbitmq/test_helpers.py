import unittest

from threatbus_rabbitmq import get_exchange_name, get_queue_name


class TestNameCreation(unittest.TestCase):
    def setUp(self):
        self.queue_name_suffix = "SUFFIX"
        self.join_pattern = "."

    def test_exchange_name_creation(self):
        data_type = "DATA_TYPE"
        self.assertEqual(
            get_exchange_name(self.join_pattern, data_type),
            "threatbus" + self.join_pattern + data_type,
        )

    def test_queue_name_creation(self):
        data_type = "DATA_TYPE"
        self.assertEqual(
            get_queue_name(self.join_pattern, data_type, self.queue_name_suffix),
            "threatbus"
            + self.join_pattern
            + data_type
            + self.join_pattern
            + self.queue_name_suffix,
        )
