from stix2_helpers import is_point_equality_ioc, split_object_path_and_value
import unittest


class TestHelpers(unittest.TestCase):
    def test_is_point_equility_ioc(self):
        # negative test
        self.assertFalse(is_point_equality_ioc("Some string"))
        self.assertFalse(is_point_equality_ioc("6.6.6.6 = ipv4-addr:value"))
        # missing brackets
        self.assertFalse(is_point_equality_ioc("ipv4-addr:value = '6.6.6.6'"))
        # double ==
        self.assertFalse(is_point_equality_ioc("[ipv4-addr:value == '6.6.6.6']"))
        # mising closing bracket
        self.assertFalse(is_point_equality_ioc("[ipv4-addr:value = '6.6.6.6'"))
        # mising opening bracket
        self.assertFalse(is_point_equality_ioc("ipv4-addr:value = '6.6.6.6']"))
        # mising quotes
        self.assertFalse(is_point_equality_ioc("[ipv4-addr:value = 6.6.6.6]"))
        # valid compound IoC
        self.assertFalse(
            is_point_equality_ioc(
                "[ipv4-addr:value = '6.6.6.6' AND domain-name:value = 'evil.com']"
            )
        )
        self.assertFalse(
            is_point_equality_ioc(
                "[ipv4-addr:value = '6.6.6.6'] AND [domain-name:value = 'evil.com']"
            )
        )

        # postitve test
        self.assertTrue(is_point_equality_ioc("[ipv4-addr:value = '6.6.6.6']"))
        self.assertTrue(is_point_equality_ioc("[ipv6-addr:value = '::1']"))
        self.assertTrue(is_point_equality_ioc("[domain-name:value = 'evil.com']"))
        self.assertTrue(
            is_point_equality_ioc(
                "[x509-certificate:hashes.'SHA-1' = '6e6187d58483457f86eae49315a0a72d7543459a']"
            )
        )

    def test_split_object_path_and_value(self):
        self.assertIsNone(split_object_path_and_value(None))
        self.assertIsNone(split_object_path_and_value(23))
        self.assertIsNone(split_object_path_and_value(True))
        self.assertIsNone(split_object_path_and_value(""))
        self.assertIsNone(split_object_path_and_value("[]"))
        self.assertIsNone(
            split_object_path_and_value(
                "[ipv4-addr:value = '6.6.6.6' AND domain-name:value = 'evil.com']"
            )
        )
        self.assertIsNone(
            split_object_path_and_value(
                "[ipv4-addr:value = '6.6.6.6'] AND [domain-name:value = 'evil.com']"
            )
        )

        self.assertEqual(
            ("ipv4-addr:value", "6.6.6.6"),
            split_object_path_and_value("[ipv4-addr:value = '6.6.6.6']"),
        )
        self.assertEqual(
            ("domain-name:value", "evil.com"),
            split_object_path_and_value("[domain-name:value = 'evil.com']"),
        )
