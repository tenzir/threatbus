#!/usr/bin/env python

import zmq

socket = zmq.Context().socket(zmq.SUB)
socket.connect("tcp://127.0.0.1:13371")
socket.setsockopt(zmq.SUBSCRIBE, b"foo")
poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)

while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
        raw = socket.recv()
        topic, message = raw.decode("utf-8").split(" ", 1)
        print(topic, message)
