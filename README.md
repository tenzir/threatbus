# Robo Investigator

The **Robo Investigor** (`robo`) autonomously performs routine task of an
incidnet response team.

## Features

We currently support the following features:

- Live correlation of threat intelligence with historical data by hooking into
  [MISP][misp]'s intelligence feeds and translating new intelligence into
  queries against [VAST][vast] (or [Tenzir][tenzir]).

## Prerequisites

You need to make sure you have the necessary Python modules, a running
[MISP][misp] instance, as well as a running [VAST][vast] node.

### Python Setup

The Python module depedencies are listed in the file
[requirements.txt](requirements.txt). An easy way to get started is to setup a
virtual environment:


```sh
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Zeek/Broker Setup

We use [Broker][broker] for the (optional) Zeek integration, which we also
install into our Python virtual environment:

```sh
export PREFIX="$(pwd)/env"
mkdir env/src
git clone git@github.com:zeek/broker.git env/src/broker
cd env/src/broker
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

### MISP Setup

First, you need to setup a MISP instance with [ZeroMQ
support][misp-zmq-config]. In the diagnostic section, make sure that the ZeroMQ
extension is up and running.

Second, you need an automation key, which is available from
`https://<misp url>/events/automation` or from your profile at
`https://<misp url>/users/view/me`. Export this key as environment variable in
your shell under `MISP_API_KEY`, e.g.:

```sh
export MISP_API_KEY=qrtyJV9VMwo2immC8S4cZEaqFEK4m13UrlTvoSGl
```

### VAST Setup

You need the `vast` (or `tenzir`) binary in your `PATH`, and a running VAST
node.

## Usage

`robo` receives intelligence items from MISP (in the form of MISP *attributes*)
and translates them data into VAST queries. Upon receiving results from the
queries, `robo` publishes them back to MISP as sightings.

Assuming your MISP instance runs at host `1.2.3.4`, you would start `robo` as
follows to receive intelligence via MISP's 0mq channel:

```sh
robo -m 1.2.3.4 --misp-zmq
```

To receive intelligence via MISP's Kafka channel, run `robo` like this:

```sh
robo -m 1.2.3.4 --misp-kafka
```

The full list of options is available via `robo -h`, e.g., to specify a
different 0mq port or to choose a different Kafka bootstrap server.

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
