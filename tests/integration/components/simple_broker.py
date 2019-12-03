#!/usr/bin/python

import broker
import sys

ep = broker.Endpoint()
subscriber = ep.make_subscriber("test")
ep.listen("127.0.0.1", 55555)


def receive():
    """ 
    Blocking one time operation that receives a single event via broker and
    returns the received event name and data as python tuple.
    """
    msg = subscriber.get()  # block until one message arrives
    topic, data = msg
    received_event = broker.zeek.Event(data)
    return received_event.name(), received_event.args()


def send(topic, name, message):
    """ 
    One time operation that sends a single message via broker.
    """
    event = broker.zeek.Event(name, message)
    ep.publish(topic, event)
