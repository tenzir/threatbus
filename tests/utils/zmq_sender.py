#!/usr/bin/env python

import zmq
import time


def send(msg):
    """Sends a single, user specified message"""
    socket = zmq.Context().socket(zmq.PUB)
    socket.bind("tcp://*:50000")
    topic = "misp_json_attribute"

    socket.send_string(f"{topic} {msg}")
    time.sleep(1)


if __name__ == "__main__":
    send("hello")
