from datetime import datetime
from dateutil import parser as dateutil_parser
from stix2 import Indicator, Sighting
from threatbus.data import ThreatBusSTIX2Constants
from typing import Dict, List


def map_bundle_to_sightings(indicator: Indicator, observations: List[Dict]):
    """
    # Generate one STIX-2 Sighting per `observed-data` entry in the list of
    STIX objects
    @param indicator: the STIX-2 indicators that all observations refer to
    @param observations: a list of STIX-2 observations to map to Sightings
    @return iterator over Sighting objects
    """
    for obj in observations:
        if obj.get("type", None) != "observed-data":
            continue
        last = dateutil_parser.parse(obj.get("last_observed", str(datetime.now())))
        yield Sighting(
            last_seen=last,
            sighting_of_ref=indicator.id,
            custom_properties={
                ThreatBusSTIX2Constants.X_THREATBUS_SIGHTING_CONTEXT.value: obj,
                ThreatBusSTIX2Constants.X_THREATBUS_INDICATOR.value: indicator,
            },
        )
