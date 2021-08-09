Threat Bus App Plugin for ZMQ Protocol
======================================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin that enables communication with any application that can
communicate via [ZeroMQ].


## Installation

```sh
pip install threatbus-zmq
```

## Configuration

The plugin uses ZeroMQ to communicate with applications, like
[pyvast-threatbus](https://github.com/tenzir/threatbus/tree/master/apps/vast).
The plugin serves three ZeroMQ endpoints to connect with. One endpoint for
managing subscriptions (and thus snapshot requests). The other two endpoints
exist for pub-sub operations.

```yaml
...
plugins:
  zmq:
    host: "127.0.0.1"
    manage: 13370
    pub: 13371
    sub: 13372
...
```

Initially, apps that want to connect with this plugin only need to know the
`manage` endpoint. The plugin and the app negotiate all other internals for
pub-sub message exchange at runtime. See the protocol definition below for
details.

## Management Protocol

Subscriptions and unsubscriptions are referred to as `management`. All
management messages are JSON formatted and exchanged via the `manage` ZMQ
endpoint that the plugin exposes.

The manage endpoint uses the
[ZeroMQ Request/Reply](https://learning-0mq-with-pyzmq.readthedocs.io/en/latest/pyzmq/patterns/client_server.html)
pattern for message exchange. That means, all messages get an immediate response
from the server. With each JSON reply, the zmq Threat Bus plugin sends a
`status` field that indicates the success of the requested operation.

### Subscribe at the Plugin

To subscribe to Threat Bus via the zmq plugin, an app needs to send a JSON
struct as follows to the `manage` endpoint of the plugin:

```
{
  "action": "subscribe",
  "topic": <TOPIC>,       # either 'threatbus/sighting' or 'threatbus/intel'
  "snapshot": <SNAPSHOT>  # number of days for a snapshot, 0 for no snapshot
}
```
In response, the app will either receive a `success` or `error` response.

- Error response:
  ```
  {
    "status": "error"
  }
  ```
- Success response:
  ```
  {
    "topic": <P2P_TOPIC>,
    "pub_port": 13371,
    "sub_port": 13372,
    "status": "success",
  }
  ```

  The `pub_port` and `sub_port` of the reply provide the port that an app should
  connect with to participate in the pub/sub message exchange. A connecting app
  can access these ports following the
  [ZeroMQ Pub/Sub](https://learning-0mq-with-pyzmq.readthedocs.io/en/latest/pyzmq/patterns/pubsub.html)
  pattern. The plugin will publish messages on the `pub_port` and accept
  messages on the `sub_port`.

  The `topic` field of the response contains a unique topic for the client. That
  topic _must_ be used to receive messages. The unique topic is a 32 characters
  wide random string and guarantees that other subscribers won't accidentally
  see traffic that should only be visible to the new client.
  
  For more details see below at `Pub/Sub via ZeroMQ`.

### Unsubscribe from the Plugin

To unsubscribe, a connected app has to send a JSON struct to the `manage`
endpoint of the plugin, as follows:

```
{
  "action": "unsubscribe",
  "topic": <P2P_TOPIC>       # the 32-characters random topic that the app got during subscription handshake
}
```

In response, the app will either receive a `success` or `error` response.

- Error response:
  ```
  {
    "status": "error"
  }
  ```
- Success response:
  ```
  {
    "status": "success"
  }
  ```

### Heartbeats

The plugin supports synchronous heartbeats from subscribed apps. Both, Threat
Bus and the connected apps benefit from heartbeats, they can mutually ensure
that the connected party is still alive.

Subscribed apps can send heartbeat messages with the following JSON format to
the `manage` endpoint of this plugin:

```
{
  "action": "heartbeat",
  "topic": <P2P_TOPIC>       # the 32-characters random topic that the app got during subscription handshake
}
```

As stated in the beginning of this section, the `manage` endpoint implements the
[ZeroMQ Request/Reply](https://learning-0mq-with-pyzmq.readthedocs.io/en/latest/pyzmq/patterns/client_server.html)
pattern. Threat Bus answers immediately to each heartbeat request with either a
`success` or `error` response.

- Error response:
  ```
  {
    "status": "error"
  }
  ```
- Success response:
  ```
  {
    "status": "success"
  }
  ```

An `error` response indicates that either Threat Bus has internal errors or that
it lost track of the app's subscription. Note: This only happens when Threat Bus
is restarted. Apps can then use that information to re-subscribe.

If Threat Bus does not answer a heartbeat message, it is either down or not
reachable (e.g., due to network issues). Plugins can use that information to try
again later.

### Pub/Sub via ZeroMQ

Once an app has subscribed to a certain Threat Bus topic using the `manage`
endpoint of the zmq plugin, it gets a unique, random `p2p_topic` (see
above). The `p2p_topic` differs from the subscribed Threat Bus topic. The
zmq plugin uses only the `p2p_topic` to publish messages to subscribers.
Messages are either STIX-2 Indicators and Sightings or are of the types
specified in
[`threatbus.data`](https://github.com/tenzir/threatbus/blob/master/threatbus/data.py),
i.e., `SnapshotRequest`, and `SnapshotEnvelope`.

ZeroMQ uses [prefix matching](https://zeromq.org/socket-api/#topics) for pub/sub
connections. The zmq plugin leverages this feature to indicate the type of
each sent message to the subscriber. Hence, an app can simply match the topic
suffix to determine the message type.

For example, all STIX-2 Indicators will always be sent on the topic
`p2p_topic + "indicator"`, all messages of the type
`threatbus.data.SnapshotRequest` on the topic `p2p_topic + "snapshotrequest"`
and so forth.

### Snapshots

Threat Bus' [snapshot](https://docs.tenzir.com/threatbus/features/snapshotting)
feature allows apps to request a snapshot during subscription. Threat Bus always
forwards snapshot requests to all app plugins. The `zmq` plugin again
forwards these `SnapshotRequests` to all connected apps. Apps, however, can
decide if they want to implement this feature, i.e., whether they respond to
`SnapshotRequest` messages or not.

`SnapshotRequests` are received like any other messages, via the `p2p_topic`. In
case the app wants to provide this feature, it must handle message of this type
(see above for an explanation of topic suffix matching).

Once the snapshot is handled, the app must use the `SnapshotEnvelope` message
type to send back messages to the plugin.

## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-vast.svg
[pypi-url]: https://pypi.org/project/threatbus-vast
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
