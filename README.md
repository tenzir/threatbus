# Robo Investigator

The **Robo Investigor** (`robo`) autonomously performs routine task of an
incidnet response team.

## Features

We currently support the following features:

- Live correlation of threat intelligence with historical data by hooking into
  [MISP][misp]'s intelligence feeds and translating new intelligence into
  queries against [VAST][vast] and [Tenzir][tenzir].

## Prerequisites

You need to make sure you have the necessary Python modules, a running
[MISP][misp] instance, as well as running [Tenzir][tenzir] or [VAST][vast]
node.

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

You need is the `vast` binary in your `PATH`, and a running VAST server with
some preloaded data listening on the default port.

## Usage

`robo` supports two modes of operation: *historical* and *continuous* queries.
A historical query looks for a specific value in the MISP database, translates
the matching attributes into a VAST query, and then publishes the VAST results
as sightings back to MISP. A continuous has a similar worflow, with the only
difference that each newly arriving attribute elicits a historical query.

The historical query feature exists primarily for ad-hoc testing. For
operational deployments, the continous query mode makes most sense. To launch
`robo` in continuous mode, and a MISP instance located at IP address `1.2.3.4`,
use the following invocation:

```sh
robo -m 1.2.3.4 -C
```

`robo` will not return until you kill the process.

You can issue a historical query for IP address `6.6.6.6` as follows:

```sh
robo -m 1.2.3.4 -H -v 6.6.6.6
```

The full list of options is available via `robo -h`.

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[tenzir]: https://docs.tenzir.com
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
