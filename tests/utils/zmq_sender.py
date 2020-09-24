#!/usr/bin/env python

import zmq
import time


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
    send("sighting", "hello", port=13371, bind=False)
    # send("sighting", "hello", bind=False)
