from datetime import datetime, timezone
import unittest
import json
from stix2 import Indicator, Sighting
from threatbus.data import Operation, ThreatBusSTIX2Constants
from .message_mapping import (
    get_vast_type_and_value,
    indicator_to_vast_matcher_ioc,
    indicator_to_vast_query,
    matcher_result_to_sighting,
    query_result_to_sighting,
    vast_escape_str,
)


class TestMessageMapping(unittest.TestCase):
    def setUp(self):
        self.ts = datetime.now(timezone.utc).astimezone()
        self.indicator_id = "indicator--46b3f973-5c03-41fc-9efe-49598a267a35"
        self.operation = Operation.REMOVE
        self.ioc_value = "evil.com"
        self.pattern = f"[domain-name:value = '{self.ioc_value}']"
        self.indicator = Indicator(
            pattern_type="stix",
            pattern=self.pattern,
            created=self.ts,
            id=self.indicator_id,
        )
        self.valid_query_result = f'{{"timestamp": "{self.ts}", "flow_id": 1840147514011873, "pcap_cnt": 626, "src_ip": "{self.ioc_value}", "src_port": 1193, "dest_ip": "65.54.95.64", "dest_port": 80, "proto": "TCP", "event_type": "http", "community_id": "1:AzSEWwmsqEKUX5qrReAHI3Rpizg=", "http": {{"hostname": "download.windowsupdate.com", "url": "/v9/windowsupdate/a/selfupdate/WSUS3/x86/Other/wsus3setup.cab?0911180916", "http_port": null, "http_user_agent": "Windows-Update-Agent", "http_content_type": "application/octet-stream", "http_method": "HEAD", "http_refer": null, "protocol": "HTTP/1.1", "status": 200, "redirect": null, "length": 0}}, "tx_id": 0}}'
        self.valid_matcher_result = f'{{"indicator": {{"value": "{self.ioc_value}", "context": "\\"threatbus__{self.indicator_id}\\""}}, "type": "zeek.dns", "event": {{"ts": "{self.ts}", "uid": "CGG3VBvnp9JKfVP56", "id.orig_h": "172.19.0.2", "id.orig_p": 37241, "id.resp_h": "1.1.1.1", "id.resp_p": 53, "proto": "udp", "trans_id": 53396, "rtt": "18.42ms", "query": "reddit.com", "qclass": 1, "qclass_name": "C_INTERNET", "qtype": 1, "qtype_name": "A", "rcode": 0, "rcode_name": "NOERROR", "AA": false, "TC": false, "RD": true, "RA": true, "Z": 2, "answers": ["151.101.193.140", "151.101.65.140", "151.101.1.140", "151.101.129.140"], "TTLs": ["2.47m", "2.47m", "2.47m", "2.47m"], "rejected": false}} }}'

    def test_vast_escape_str(self):
        self.assertEqual(vast_escape_str('e"vil.com'), 'e\\"vil.com')
        self.assertEqual(vast_escape_str('"evil.com"'), '\\"evil.com\\"')
        self.assertEqual(vast_escape_str("e\\vil.com"), "e\\\\vil.com")
        self.assertEqual(vast_escape_str('e\\"vil.com'), 'e\\\\\\"vil.com')
        self.assertEqual(vast_escape_str('e\\\\""vil.com'), 'e\\\\\\\\\\"\\"vil.com')
        self.assertEqual(vast_escape_str("e'vil.com"), "e'vil.com")

    def test_invalid_get_vast_type_and_value(self):
        self.assertIsNone(get_vast_type_and_value(None))
        self.assertIsNone(get_vast_type_and_value(True))
        self.assertIsNone(get_vast_type_and_value(23))
        self.assertIsNone(get_vast_type_and_value(""))
        self.assertIsNone(get_vast_type_and_value("[]"))
        self.assertIsNone(get_vast_type_and_value("[ipv4-addr:value = '6"))

    def test_get_vast_type_and_value(self):
        self.assertEqual(
            ("ip", "6.6.6.6"), get_vast_type_and_value("[ipv4-addr:value = '6.6.6.6']")
        )
        self.assertEqual(
            ("ipv6", "::1"), get_vast_type_and_value("[ipv6-addr:value = '::1']")
        )
        self.assertEqual(
            ("domain", "example.com"),
            get_vast_type_and_value("[domain-name:value = 'example.com']"),
        )
        url = "example.com/foo?query=bar"
        self.assertEqual(
            ("url", url), get_vast_type_and_value(f"[url:value = '{url}']")
        )

    def test_invalid_indicator_to_vast_matcher_ioc(self):
        self.assertIsNone(indicator_to_vast_matcher_ioc(None))
        self.assertIsNone(indicator_to_vast_matcher_ioc(42))
        self.assertIsNone(indicator_to_vast_matcher_ioc(True))
        self.assertIsNone(indicator_to_vast_matcher_ioc("hello"))
        self.assertIsNone(
            indicator_to_vast_matcher_ioc(Sighting(sighting_of_ref=self.indicator_id))
        )

    def test_indicator_to_vast_matcher_ioc(self):
        expected_vast_ioc = {
            "value": self.ioc_value,
            "type": "domain",
            "reference": f"threatbus__{self.indicator_id}",
        }
        self.assertEqual(
            expected_vast_ioc, indicator_to_vast_matcher_ioc(self.indicator)
        )

    def test_invalid_indicator_to_vast_query(self):
        self.assertIsNone(indicator_to_vast_query(None))
        self.assertIsNone(indicator_to_vast_query(42))
        self.assertIsNone(indicator_to_vast_query(True))
        self.assertIsNone(indicator_to_vast_query("hello"))
        self.assertIsNone(
            indicator_to_vast_query(Sighting(sighting_of_ref=self.indicator_id))
        )

    def test_indicator_to_vast_query(self):
        ## test IP
        ip = "6.6.6.6"
        expected_vast_query = f"{ip}"
        ioc = Indicator(pattern_type="stix", pattern=f"[ipv4-addr:value = '{ip}']")
        self.assertEqual(expected_vast_query, indicator_to_vast_query(ioc))

        ## test URL
        url = "example.com/foo/bar?query=123"
        expected_vast_query = f'"{url}" == net.uri'
        ioc = Indicator(pattern_type="stix", pattern=f"[url:value = '{url}']")
        self.assertEqual(expected_vast_query, indicator_to_vast_query(ioc))

        ## test domain
        domain = "example.com"
        expected_vast_query = f'"{domain}" == net.domain || "{domain}" == net.hostname'
        ioc = Indicator(
            pattern_type="stix", pattern=f"[domain-name:value = '{domain}']"
        )
        self.assertEqual(expected_vast_query, indicator_to_vast_query(ioc))

    def test_invalid_query_result_to_sighting(self):
        # valid query result, invalid Indicator
        self.assertIsNone(query_result_to_sighting(self.valid_query_result, None))
        self.assertIsNone(query_result_to_sighting(self.valid_query_result, 42))
        self.assertIsNone(query_result_to_sighting(self.valid_query_result, object))
        self.assertIsNone(query_result_to_sighting(self.valid_query_result, True))
        self.assertIsNone(query_result_to_sighting(self.valid_query_result, "XX"))

        # invalid query result, valid Indicator
        self.assertIsNone(query_result_to_sighting(None, self.indicator))
        self.assertIsNone(query_result_to_sighting(42, self.indicator))
        self.assertIsNone(query_result_to_sighting(object, self.indicator))
        self.assertIsNone(
            query_result_to_sighting("some non-json string", self.indicator)
        )

    def test_query_result_to_sighting(self):
        parsed_sighting = query_result_to_sighting(
            self.valid_query_result, self.indicator
        )
        self.assertIsNotNone(parsed_sighting)
        self.assertEqual(type(parsed_sighting), Sighting)
        self.assertEqual(parsed_sighting.last_seen, self.ts)
        self.assertEqual(parsed_sighting.sighting_of_ref, self.indicator_id)
        self.assertTrue(
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value
            in parsed_sighting
        )
        expected_context = json.loads(self.valid_query_result)
        expected_context["source"] = "VAST"
        self.assertEqual(parsed_sighting.x_threatbus_sighting_context, expected_context)

    def test_invalid_matcher_result_to_sighting(self):
        self.assertIsNone(matcher_result_to_sighting(None))
        self.assertIsNone(matcher_result_to_sighting(42))
        self.assertIsNone(matcher_result_to_sighting(object))
        self.assertIsNone(matcher_result_to_sighting("some non-json string"))
        sighting_with_malformed_reference = '{"ts": "2020-09-24T08:43:43.654072335", "value": "foo", "reference": "threatbus__86"}'
        self.assertIsNone(matcher_result_to_sighting(sighting_with_malformed_reference))
        sighting_with_malformed_timestamp = '{"ts": "2020 T08 :43.654072335", "value": "foo", "reference": "threatbus__indicator--46b3f973-5c03-41fc-9efe-49598a267a35"}'
        self.assertIsNone(matcher_result_to_sighting(sighting_with_malformed_timestamp))

    def test_matcher_result_to_sighting(self):
        parsed_sighting = matcher_result_to_sighting(self.valid_matcher_result)
        self.assertIsNotNone(parsed_sighting)
        self.assertEqual(type(parsed_sighting), Sighting)
        self.assertEqual(parsed_sighting.last_seen, self.ts)
        self.assertEqual(parsed_sighting.sighting_of_ref, self.indicator_id)
        self.assertTrue(
            ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value
            in parsed_sighting
        )
        expected_context = {"source": "VAST"}
        self.assertEqual(parsed_sighting.x_threatbus_sighting_context, expected_context)
