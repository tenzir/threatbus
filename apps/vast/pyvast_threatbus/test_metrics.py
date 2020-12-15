import unittest
from sys import maxsize as max_integer
from .metrics import Gauge, Summary


class TestGauge(unittest.TestCase):
    def setUp(self):
        self.g = Gauge("test_gauge")

    def test_init(self):
        self.assertFalse(self.g.is_set)
        self.assertEqual(self.g.value, 0)

    def test_inc(self):
        self.g.inc()
        self.assertEqual(self.g.value, 1)
        self.assertTrue(self.g.is_set)

    def test_dec(self):
        self.g.dec()
        self.assertEqual(self.g.value, -1)
        self.assertTrue(self.g.is_set)

    def test_reset(self):
        self.g.inc()
        self.assertTrue(self.g.is_set)

        self.g.reset()
        self.assertFalse(self.g.is_set)
        self.assertEqual(self.g.value, 0)


class TestSummary(unittest.TestCase):
    def setUp(self):
        self.s = Summary("test_summary")

    def test_init(self):
        self.assertFalse(self.s.is_set)
        self.assertEqual(self.s._sum, 0)
        self.assertEqual(self.s._count, 0)
        self.assertEqual(self.s.min, max_integer)
        self.assertEqual(self.s.max, 0)
        self.assertEqual(self.s.avg, 0)

    def test_observe(self):
        observation = 5
        self.s.observe(5)
        self.assertTrue(self.s.is_set)
        self.assertEqual(self.s._sum, observation)
        self.assertEqual(self.s._count, 1)  # invoked once
        self.assertEqual(self.s.min, observation)
        self.assertEqual(self.s.max, observation)
        self.assertEqual(self.s.avg, observation)

    def test_observe_multiple(self):
        self.s.observe(1)
        self.s.observe(2)
        self.s.observe(3)
        self.s.observe(4)
        self.s.observe(5)
        self.s.observe(10)

        self.assertTrue(self.s.is_set)
        self.assertEqual(self.s._sum, 25)  # 1+2+3+4+5+10
        self.assertEqual(self.s._count, 6)  # invoked 6 times
        self.assertEqual(self.s.min, 1)
        self.assertEqual(self.s.max, 10)
        self.assertEqual(self.s.avg, 25 / 6)

    def test_reset(self):
        self.s.observe(5)
        self.assertTrue(self.s.is_set)

        self.s.reset()
        self.assertFalse(self.s.is_set)
        self.assertEqual(self.s._sum, 0)
        self.assertEqual(self.s._count, 0)
        self.assertEqual(self.s.min, max_integer)
        self.assertEqual(self.s.max, 0)
        self.assertEqual(self.s.avg, 0)
