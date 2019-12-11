# Threat Bus

The **Threat Bus** (`threat-bus`) autonomously performs routine task of an
incident response team.

In abstract terms, `threat-bus` implements threat intelligence *producers* and
*consumers* that can interact with each other bidirectionally. This enables
novel use cases, e.g., to correlation indicators of compromise in real time or
to perform historical intelligence lookups.

Currently, `threat-bus` supports the following producers:

- [MISP][misp]: export attributes

The following consumers exist:

- [VAST][vast] (or [Tenzir][tenzir]): for historical intel queries
- [Zeek][zeek]: ship intel into Zeek

## Test & Develop

Use the `Makefile` to format the python code and execute tests.

```sh
$ make format
$ make unit-test
$ make integration-test
```

Or use `make all` to run all the above commands at once.

### Integration Tests

For the integration tests to succeed, you require a running MISP instance. As
for now, you can use [docker-misp](https://github.com/misp/docker-misp).

Set up MISP:

```sh
git clone https://github.com/misp/docker-misp.git
cd docker-misp
docker build \
    --rm=true --force-rm=true \
    --build-arg MYSQL_MISP_PASSWORD=admin \
    --build-arg POSTFIX_RELAY_HOST=localhost \
    --build-arg MISP_FQDN=localhost \
    --build-arg MISP_EMAIL=admin@admin.test \
    --build-arg MISP_GPG_PASSWORD=admin \
    -t integration-misp container

mkdir <some/tmp/dir/for/data-base>

## initialize db, mounted from <some/tmp/dir/for/data-base>
docker run -t -p 443:443 -p 80:80 -p 3306:3306 -p 50000:50000 -v <some/tmp/dir/for/data-base>:/var/lib/mysql integration-misp:latest /init-db

## run in foreground
docker run -t -p 443:443 -p 80:80 -p 3306:3306 -p 50000:50000 -v <some/tmp/dir/for/data-base>:/var/lib/mysql integration-misp:latest
```

Execute integration tests for `threath-bus` via `make integration-tests`. Afterwards
you can stop / kill the MISP instance in docker again.

## Installation

### OS Packages

Threat Bus integrates with zeroMQ [0mq](https://zeromq.org/) and
[confluent-kafka](https://www.confluent.io/). Hence you have to install these
tools locally for the python bindings link against those packages.

### Python Setup

#### Package Installation

Threat Bus requires the Python modules listed in
[requirements.txt](requirements.txt). We recommend to get started with a Python
virtual environment until you have working deployment:

```sh
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

#### Python Path

Threat Bus comes as a python module, all sources are to be found in the
`threatbus` folder (whitout hyphen, because python modules don't have hyphens).

In order to make the development with relative imports possible, and without
having to install the project, you must export your PYTHONPATH:

  $ export PYTHONPATH=$PYTHONPATH:/home/<you>/code/threat-bus/threatbus

### MISP Producer

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

Alternatively, you can place the API key in the configuration file. An existing
environment variable will always take precedence to the configuration file.

### VAST Consumer

For the VAST consumer, you only need to ensure that the `vast` binary is found
in the `PATH` environment variable. Alternatively, you can specify a custom
location in the configuration file.

### Zeek/Broker Consumer

We use [Broker][broker] for the Zeek consumer. The easist solution is to
install Broker into a Python virtual environment:

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

Finally, we make sure that we find the Broker Python modules in the virtual
environment without setting `PYTHONPATH` to `$PREFIX/lib/python`:

```sh
site_packages=$(python -c "import site; print(site.getsitepackages()[0])")
cp sitecustomize.py $site_packages
```

## Usage

The general architecture of `threat-bus` resembles a publish/subscribe system:
subscriptions to intelligence producers generate a stream of indicators that
`threat-bus` translates for various intel consumers.

The [example configuration file](config.yaml) illustrates how to configure a
deployment. After customizing the values to your environment, launch `threat-bus`
with a configuration:

```sh
threat-bus -c custom.yaml
```

For ease of use, a subset of the configuration values can be overriden on the
command line. For example, to override the MISP REST API URL and Zeek host, you
can use:

```sh
threat-bus -m https://1.2.3.4:8080 -z 5.6.7.8
```

The full list of overriding options is available via `threat-bus -h`.

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[zeek]: https://www.zeek.org
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
