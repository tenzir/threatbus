#!/usr/bin/env python

from queue import Queue
import zmq
import sys


def send_manage_message(action, topic):
    """
    Un/subscribes to Threat Bus for the given topic.
    @param action Either 'subscribe' or 'unsubscribe'
    @param topic The topic to subscribe to
    """
    action = {"action": action, "topic": topic}
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect("tcp://127.0.0.1:13370")
    socket.send_json(action)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    if poller.poll(5000):
        return socket.recv_json()
    socket.close()
    context.term()
    return "Unsuccessfull"


def receive(n: int, topics: list):
    """
    Subscribes to Threat Bus. Receives exactly n items for any of the given
    topics (list), then unsubscribes.
    @param n Items to receive
    @param topics List of topics to subscribe to
    """
    socket = zmq.Context().socket(zmq.SUB)
    socket.connect("tcp://127.0.0.1:13371")
    p2p_topics = []
    for topic in topics:
        res = send_manage_message("subscribe", topic)
        socket.setsockopt(zmq.SUBSCRIBE, res["topic"].encode())
        p2p_topics.append(res["topic"])
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)

    for _ in range(n):
        socks = dict(poller.poll(timeout=None))
        if socket in socks and socks[socket] == zmq.POLLIN:
            raw = socket.recv()
            topic, message = raw.decode("utf-8").split(" ", 1)
            yield (topic, message)
    for topic in p2p_topics:
        send_manage_message("unsubscribe", topic)


def forward(n: int, topics: list, q: Queue):
    """
    Receives exactly n messages via ZeroMQ and forwards them to the result queue
    @param n Items to receive
    @param topics List of topics to subscribe to
    @param q The queue to push received items to
    """
    for _, msg in receive(n, topics):
        q.put(msg)


if __name__ == "__main__":
    count = 200
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    for topic, msg in receive(count, ["stix2/indicator", "stix2/sighting"]):
        print(topic, msg)
