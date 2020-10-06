Threat Bus MISP Plugin
======================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin that enables communication to [MISP](https://www.misp-project.org/).

The plugin goes against the pub/sub architecture of Threat Bus (for now),
because the plugin subscribes a listener to ZeroMQ / Kafka, rather than having
MISP subscribe itself to Threat Bus. That will be addressed with a MISP module
in the near future.

## Installation

```sh
pip install threatbus-misp
```

#### Prerequisites

*Install Kafka on the Threat Bus host*

The plugin enables communication either via ZeroMQ or Kafka. When using Kafka,
you have to install `librdkafka` for the host system that is running
`threatbus`. See also the [prerequisites](https://github.com/confluentinc/confluent-kafka-python#prerequisites)
section of the `confluent-kafka` python client.

## Configuration

The plugin can either use ZeroMQ or Kafka to retrieve intelligence items from
MISP. It uses the MISP REST api to report back sightings of indicators.

ZeroMQ and Kafka are mutually exclusive, such that Threat Bus does not receive
all attribute updates twice. See below for an example configuration.


```yaml
...
plugins:
  misp:
    api:
      host: https://localhost
      ssl: false
      key: MISP_API_KEY
    filter: # filter are optional. you can omit the entire section.
      - orgs: # org IDs must be strings: https://github.com/MISP/PyMISP/blob/main/pymisp/data/schema.json
          - "1"
          - "25"
        tags:
          - "TLP:AMBER"
          - "TLP:RED"
        types: # MISP attribute types https://github.com/MISP/misp-objects/blob/main/schema_objects.json
          - ip-src
          - ip-dst
          - hostname
          - domain
          - url
      - orgs:
        - "2"
    zmq:
      host: localhost
      port: 50000
    #kafka:
    #  topics:
    #  - misp_attribute
    #  poll_interval: 1.0
    #  # All config entries are passed as-is to librdkafka
    #  # https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
    #  config:
    #    bootstrap.servers: "localhost:9092"
    #    group.id: "threatbus"
    #    auto.offset.reset: "earliest"
...
```

### Filter

The plugin can be configured with a list of filters. Every filter describes a
whitelist for MISP attributes (IoCs). The MISP plugin will only forward IoCs to
Threat Bus if the whitelisted properties are present.

A filter consists of three sub-whitelists for organizations, types, and tags.
To pass through the filter, an attribute must provide at least one of the
whitelisted properties of each of the whitelists. More precisely, entries of
each whitelist are linked by an `"or"`-function, the whitelists themselves are
linked by an `"and"`-function, as follows:
`(org_1 OR org_2) AND (type_1 OR type_2) AND (tag_1 OR tag_2)`.

The MISP plugin always assumes that the *absence of a whitelist means that
everything is whitelisted*. For example, when the entire `filter` section is
omitted from the config, then all attributes are forwarded and nothing is
filtered. More examples follow below.

#### Organizations

Organizations are whitelisted by their ID, which is a
[string](https://github.com/MISP/PyMISP/blob/main/pymisp/data/schema.json). Only
those MISP attributes that come from any of the whitelisted organizations will
be forwarded to Threat Bus.

#### Types

Types can be whitelisted by specifying MISP
[attribute types](https://github.com/MISP/misp-objects/blob/main/schema_objects.json).
Only those attributes that are instances of a whitelisted type will be forwarded
to Threat Bus.

#### Tags

MISP Attributes can be tagged with arbitrary strings. The tag whitelist respects
tag *names*. Only those attributes that have at least one of the whitelisted
tags will be forwarded to Threat Bus.

#### Examples:

This section provides some simple configuration examples to illustrate how
whitelist filtering works.

1. Forward all IoCs from the organizations `"1"` and `"25"`
  ```yaml
  - orgs:
    - "1"
    - "25"
  ```
2. Forward only IoCs of the `domain`, `url`, or `uri` type, but only if they
  come from the organization `"1"` or `"25"`.
  ```yaml
  - orgs:
    - "1"
    - "25"
  - types:
    - domain
    - url
    - uri
  ```
2. Forward only IoCs that are tagged with `TLP:RED` or `TLP:AMBER`, but only of
  type `"src-ip"`:
  ```yaml
  - tags:
    - "TLP:RED"
    - "TLP:AMBER"
  - types:
    - src-ip
  ```

## Development Setup

The following guides describe how to set up local, dockerized instances of MISP
and Kafka.

### Dockerized Kafka

For a simple, working Kafka Docker setup use the [single node example](https://github.com/confluentinc/cp-docker-images/blob/5.3.1-post/examples/kafka-single-node/docker-compose.yml)
from `confluentinc/cp-docker-images`.

Store the `docker-compose.yaml` and modify the Kafka environment variables such
that the Docker host (e.g., `172.17.0.1`) of your Docker machine is advertised
as Kafka listener:

```yaml
zookeeper:
  ...
kafka:
  ...
  environment:
    KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:29092,PLAINTEXT_HOST://172.17.0.1:9092   # <-- That is the IP of your Docker host
    KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
  ...
```

For details about Kafka listeners, check out [this article](https://rmoff.net/2018/08/02/kafka-listeners-explained/).

Then start the compose setup via `docker-compose up -d`.

To test the setup, use the `tests/utils/kafka_receiver.py` and
`tests/utils/kafka_sender.py` scripts.


### Dockerized MISP

Use DCSO's [dockerized MISP](https://github.com/DCSO/MISP-dockerized) to set
up a local testing environment:

*Setup a MISP Docker cluster*

```
git clone git@github.com:DCSO/MISP-dockerized.git
cd MISP-dockerized
make install
# follow the dialog...
```

*Edit the docker-compose.yaml*

```sh
cd current
vim docker-compose.yaml
```
Find the section `misp-server` in the configuration and add the following:

```yaml
misp-server:
    ...
    ports:
      - "50000:50000"
    ...
```


*Restart MISP to accept the new port*

```sh
make deploy
```

*Enable the Kafka plugin in the MISP webview*

- Visit https://localhost:80
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the following entries 
  - `Plugin.Kafka_enable` -> `true`
  - `Plugin.Kafka_brokers` -> `172.17.0.1:9092`    <- In this example, 172.17.0.1 is the Docker host, reachable from other Docker networks. The port is reachable when the Kafka Docker setup binds to it globally.
  - `Plugin.Kafka_attribute_notifications_enable` -> `true`
  - `Plugin.Kafka_attribute_notifications_topic` -> `misp_attribute` <- The topic goes into the threatbus `config.yaml`

*Install Kafka inside the `misp-server` container*

```sh
docker exec -ti misp-server bash # pop interactive shell inside the container

apt-get install software-properties-common
apt-get update
# enable stretch-backports to get a recent librdkafka version
add-apt-repository "deb http://deb.debian.org/debian stretch-backports main contrib non-free"
apt-get update
apt-get install librdkafka-dev/stretch-backports
# see https://misp.github.io/MISP/INSTALL.ubuntu1804/#misp-has-a-feature-for-publishing-events-to-kafka-to-enable-it-simply-run-the-following-commands
pecl channel-update pecl.php.net
pecl install rdkafka
echo "extension=rdkafka.so" | tee /etc/php/7.0/mods-available/rdkafka.ini
phpenmod rdkafka
service apache2 restart
exit # leave the Docker container shell
```

*Enable the ZMQ plugin in the MISP webview*

- Visit https://localhost:80
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Diagnostics Tab`
- Find the ZeroMQ plugin section and enable it
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the entry `Plugin.ZeroMQ_attribute_notifications_enable` to `true`

*Restart all MISP services*

```sh
make restart-all
```


## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-misp.svg
[pypi-url]: https://pypi.org/project/threatbus-misp
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
