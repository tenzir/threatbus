# Robo Investigator

The **Robo Investigor** (`robo`) autonomously performs routine task of an
incident response team.

In particular, `robo` performs live correlation of threat intelligence with
historical data by hooking into [MISP][misp]'s intelligence feeds and
dispatching new intelligence into to downstream consumers. We support the
following consumers:

- [VAST][vast] (or [Tenzir][tenzir]): perform historical queries
- [Zeek][zeek]: convert MISP intel into Zeek intel

## Installation

You need a running [MISP][misp] instance and at least one intel consumer.

### Python Setup

The Python module depedencies are listed in the file
[requirements.txt](requirements.txt). An easy way to get started is to setup a
virtual environment:


```sh
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### MISP Setup

First, you need to setup a MISP instance with [0mq][misp-zmq-config] or
[Kafka][kafka] support. In the diagnostic section, make sure that the the
plugin is up and running. The 0mq plugin is usally enabled by default, but the
Kafka plugin requires explicit activation. In addition to enabling the Kafka
plugin globally via `Plugin.Kafka_enable`, you need to set your Kafka brokers
via `Plugin.Kafka_brokers` and set
`Plugin.Kafka_attribute_notifications_enable` to `true`.

Second, you need an automation key, which is available from
`https://<misp url>/events/automation` or from your profile at
`https://<misp url>/users/view/me`. Export this key as environment variable in
your shell under `MISP_API_KEY`, e.g.:

```sh
export MISP_API_KEY=qrtyJV9VMwo2immC8S4cZEaqFEK4m13UrlTvoSGl
```

### VAST/Tenzir Integration

For the VAST/Tenzir consumer, you only need to ensure that the `vast` or
`tenzir` binary is found in the `PATH` environment variable. Alternatively, you
can specify a custom location via `--vast-executable`.

### Zeek/Broker Integration

We use [Broker][broker] for the Zeek consumer. The easist solution is to
install Broker inteo a Python virtual environment:

```sh
export PREFIX="$(pwd)/env"
mkdir env/src
git clone git@github.com:zeek/broker.git env/src/broker
cd env/src/broker
git checkout v1.1.2 # for Zeek 2.6.1
git submodule update --recursive --init
./configure --generator=Ninja --prefix=$PREFIX --with-python=$PREFIX/bin/python
cd build
ninja
ninja install
cd ../../..
```

Finally, we make sure that we find the Broker Python modules without setting
`PYTHONPATH` to `$PREFIX/lib/python`:

```sh
site_packages=$(python -c "import site; print(site.getsitepackages()[0])")
cp sitecustomize.py $site_packages
```

## Usage

The general architecture of `robo` resembles a publish/subscribe system:
subscriptions to intelligence producers generate a stream of indicators that
`robo` translates for various intel consumers.

The [example configuration file](config.yaml) illustrates how to configure a
deployment. After customizing the values to your environment, launch `robo`
with a configuration:

```sh
robo -c custom.yaml
```

For ease of use, a subset of the configuration values can be overriden on the
command line. For example, to override the MISP and Zeek host, you can use:

```sh
robo -m 1.2.3.4 -z 5.6.7.8
```

The full list of overriding options is available via `robo -h`.

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[zeek]: https://www.zeek.org
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
