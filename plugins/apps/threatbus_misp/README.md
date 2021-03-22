Threat Bus MISP Plugin
======================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin that enables communication with [MISP](https://www.misp-project.org/).

The plugin goes against the pub/sub architecture of Threat Bus (for now),
because it actively binds to a single MISP instance to receive attribute
(IoC) updates, and report back sightings via the REST API. Following the strict
pub/sub architecture of Threat Bus, it *should be the other way
around*, with MISP binding to Threat Bus. This will eventually be resolved by a
MISP module.

For now, the plugin supports two ways to retrieve attribute (IoC) updates from
MISP - either via ZeroMQ or via Kafka. Basically, the plugin makes itself a
subscriber to MISP events.

## Installation

Users can specify *optional dependencies* during installation. The plugin uses
either ZeroMQ or Kafka to get IoC updates from MISP. As we don't want to burden
the user to install unused dependencies, both options are available as follows:


```sh
pip install threatbus-misp[zmq]
pip install threatbus-misp[kafka]
```

If neither of these dependencies is installed (i.e., you installed
`threatbus-misp` without the `[...]` suffix for optional deps), the plugin throws
an error and exits immediately.

**Depending on your setup, you might want to use quotes to avoid shell expansion
when using `[...]`**. For example, you can do `pip install ".[zmq]"` for local
development.

### Kafka Prerequisites

When you decide to use Kafka to receive IoC updates from MISP, you first need to
install Kafka on the Threat Bus host. This plugin uses the
[confluent-kafka](https://docs.confluent.io/platform/current/clients/confluent-kafka-python/index.html)
Python package which requires `librdkafka`. See also the
[prerequisites](https://github.com/confluentinc/confluent-kafka-python#prerequisites)
section of the `confluent-kafka` Python client for details about setting it up
for your distribution.

Once installed, go ahead and install the Kafka version of this plugin:

```
pip install threatbus-misp[kafka]
```

## Configuration

The plugin uses the MISP REST API to report back sightings of IoCs. You need to
specify a MISP API key for it to work.

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

### IoC Filter

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

The following guides describe how to set up a local, dockerized instance of
Kafka and how to setup a VirtualBox running MISP for developing.

### Dockerized Kafka

For a simple, working Kafka Docker setup use the
[single node example](https://github.com/confluentinc/cp-docker-images/blob/5.3.1-post/examples/kafka-single-node/docker-compose.yml)
from `confluentinc/cp-docker-images`.

Store the `docker-compose.yaml` and modify the Kafka environment variables such
that the Docker host (e.g., `172.17.0.1` on Linux) of your Docker machine is
advertised as Kafka listener:

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

Check out [this article](https://rmoff.net/2018/08/02/kafka-listeners-explained/)
for details about Kafka listeners.

Then start the compose setup via `docker-compose up -d`.

To test the setup, use the `tests/utils/kafka_receiver.py` and
`tests/utils/kafka_sender.py` scripts.


### Local MISP using VirtualBox

This guide walks you through setting up MISP using a pre-configured VirtualBox
VM and then configuring MISP to export Attribute (IoC) updates to Threat Bus.

#### Installation via VirtualBox

Use the officially maintained
[Virtual Images](https://www.circl.lu/misp-images/_archive/) for MISP.
Download the latest `.ova` image file and load it in a VirtualBox client. Ensure
the following:

- The VM has enough working memory (e.g., 3 GiB of RAM)
- The VM exposes ports 8443 (web interface) and 50000 (ZMQ)
  - Use VirtualBox port-forwarding when NATting
  - Use VirtualBox bridge-mode & SSH into the VM using SSH port-forwarding

Here are the above steps as pure CLI instructions for running MISP in headless
mode (i.e., without a graphical VirtualBox interface).

```
curl -fL -o misp-2.4.138.ova https://www.circl.lu/misp-images/latest/MISP_v2.4.138@28ccbc9.ova
vboxmanage import misp-2.4.138.ova --vsys 0 --vmname misp --memory 3072 --cpus 1 --eula accept
vboxmanage modifyvm misp --nic1 nat
vboxmanage modifyvm misp --natpf1 "zmq,tcp,,50000,,50000"
vboxmanage list -l misp
```

You can then start and stop VM using the following commands:

```
vboxmanage startvm misp --type headless
vboxmanage controlvm misp poweroff
```

#### Configuration for usage with Threat Bus

For Threat Bus to receive attribute (IoC) updates from MISP, you must either
enable Kafka or ZMQ export in the MISP VM. If you chose to go with Kafka, you
need to install `librdkafka` first inside the VM, then make it known to PHP.

*Install Kafka inside the VM*

```sh
ssh misp@<MISP_VM_IP> # enter your configured password to pop an interactive shell inside the VM
sudo apt-get update
sudo apt-get install software-properties-common
sudo apt-get install librdkafka-dev

# see https://misp.github.io/MISP/INSTALL.ubuntu1804/#misp-has-a-feature-for-publishing-events-to-kafka-to-enable-it-simply-run-the-following-commands
sudo pecl channel-update pecl.php.net
sudo pecl install rdkafka
echo "extension=rdkafka.so" | sudo tee /etc/php/7.2/mods-available/rdkafka.ini
sudo phpenmod rdkafka
sudo service apache2 restart
exit
```

Once Kafka is installed, you can go ahead and enable it in the MISP web-view.

*Enable Kafka export in the MISP web-view*

- Visit https://localhost:8443
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the following entries 
  - `Plugin.Kafka_enable` -> `true`
  - `Plugin.Kafka_brokers` -> `172.17.0.1:9092`    <- In this example, 172.17.0.1 is the Docker host as configured in the Dockerized Kafka setup above, reachable from other Docker networks. The port is reachable when the Kafka Docker setup binds to it globally.
  - `Plugin.Kafka_attribute_notifications_enable` -> `true`
  - `Plugin.Kafka_attribute_notifications_topic` -> `misp_attribute` <- The topic goes into the threatbus `config.yaml`

You can use ZeroMQ to export IoCs from MISP as light weight alternative to
running Kafka. It does not require any extra installations, except enabling the
feature in the MISP web-view.

*Enable the ZMQ plugin in the MISP web-view*

- Visit https://localhost:8443
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Diagnostics Tab`
- Find the ZeroMQ plugin section and enable it
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the entry `Plugin.ZeroMQ_attribute_notifications_enable` to `true`


## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-misp.svg
[pypi-url]: https://pypi.org/project/threatbus-misp
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
