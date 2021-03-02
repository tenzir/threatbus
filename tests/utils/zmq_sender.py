#!/usr/bin/env python

import zmq
import time
from stix2 import Indicator, Sighting


def send(topic, msg, host="127.0.0.1", port=50000, bind=True):
    """Sends a single, user specified message"""
    socket = zmq.Context().socket(zmq.PUB)
    if bind is True:
        socket.bind(f"tcp://{host}:{port}")
        time.sleep(0.5)
    else:
        socket.connect(f"tcp://{host}:{port}")
        time.sleep(0.5)
    # print(f"send string: {topic} {msg}")
    socket.send_string(f"{topic} {msg}")
    time.sleep(0.5)


if __name__ == "__main__":
    indicator = Indicator(
        pattern="[domain-name:value = 'evil.com']", pattern_type="stix"
    )
    sighting = Sighting(
        sighting_of_ref="indicator--629a6400-8817-4bcb-aee7-8c74fc57482c",
        custom_properties={"x_threatbus_source": "VAST"},
    )
    send("stix2/indicator", indicator.serialize(), port=13372, bind=False)
    send("stix2/sighting", sighting.serialize(), port=13372, bind=False)
