
<h1 align="center">
  Threat Bus
</h1>
<h4 align="center">

A threat intelligence dissemination layer for open-source security tools.

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![Total alerts][lgtm-alerts-badge]][lgtm-alerts-url]
[![Language grade: Python][lgtm-quality-badge]][lgtm-quality-url]
[![Development Status][beta-badge]][latest-release-url]
[![Latest Release][latest-release-badge]][latest-release-url]
[![License][license-badge]][license-url]

[_Getting Started_](#getting-started) &mdash;
[_Contributing Guidelines_][contributing-url] &mdash;
[_Writing Plugins_](#plugin-development) &mdash;
[_License_](#license) &mdash;
[_Documentation_][docs]
</h4>
<div align="center">

[![Chat][chat-badge]][chat-url]
</div>

## Key Features

- **Connect Open-Source Security Tools**: Threat Bus is a pub-sub broker for
  threat intelligence data. With *Threat Bus* you can seamlessly integrate
  threat intel platforms like [OpenCTI][opencti] or [MISP][misp] with detection
  tools and databases like [Zeek][zeek] or [VAST][vast].

- **Native STIX-2**: Threat Bus transports indicators and sightings encoded as
  per the [STIX-2](https://oasis-open.github.io/cti-documentation/stix/intro)
  open format specification.

- **Plugin-based Architecture**: The project is plugin-based and can be extended
  easily. Read about the different [plugin types][plugin-types] and
  [how to write your own][plugin-development].
  We welcome contributions to adopt new open source tools!

- **Official Plugins**: We maintain many plugins right in the official Threat
  Bus repository. Check out our integrations for [MISP][misp], [Zeek][zeek],
  [CIFv3][cif], and generally apps that connect via [ZeroMQ][zmq], like
  [vast-threatbus][vast-threatbus] and our
  [OpenCTI connector][opencti-connector].

- **Snapshotting**: The snapshot feature allows subscribers to directly request
  threat intelligence data for a certain time range from other applications.
  Threat Bus handles the point-to-point communication of all involved apps.


## Getting Started

The `config.yaml.example` file provides a working configuration for Threat Bus
with all existing application plugins enabled together with the RabbitMQ
backbone.

The following example shows how to connect [Zeek][zeek] via Threat Bus. There
are more integrations available, so make sure to check out all
[Threat Bus projects on PyPI](https://pypi.org/search/?q=threatbus).

The example assumes that `threatbus` is available in your PATH. See the
section on [Installation](#installation) below for more information on how to
get there.

*Start Threat Bus*

```sh
threatbus
```

*Start with a specially named config file*

The `config.yaml.example` file in this directory gives an overview of
the available config keys and their default values.

```sh
threatbus -c /path/to/your/special-config.yaml
```

*Environment variables take precedence over config file values. Prefix
everything with `THREATBUS_`*

```sh
export THREATBUS_LOGGING__CONSOLE=true
threatbus -c /path/to/your/special-config.yaml
```

Note that you must use a double underscores `__` in your env to refer to nested
config variables.

*Start Zeek as Threat Bus app*

```sh
zeek -i <INTERFACE> -C ./apps/zeek/threatbus.zeek
```

*Start Zeek and request a snapshot*

```sh
zeek -i <INTERFACE> -C ./apps/zeek/threatbus.zeek "Tenzir::snapshot_intel=30 days"
```

Threat Bus also ships as pre-built Docker image and is available on
[Docker Hub](https://hub.docker.com/r/tenzir/threatbus).

*Use the Threat Bus Docker container*

```sh
docker run tenzir/threatbus:latest --help
```

*Start Threat Bus container with a custom config file*

```sh
docker run -p 47661:47661 -v $PWD/my-custom-config.yaml:/opt/tenzir/threatbus/my-custom-config.yaml tenzir/threatbus:latest -c my-custom-config.yaml
```

Tip: Threat Bus checks for config files with default names. If you mount your
config file to `/opt/tenzir/threatbus/config.yaml`, you can start the
application without specifying the config file location with the `-c` parameter.

## Installation

Install `threatbus` and all plugins that you require. Optionally, use a virtual
environment.

Note that Threat Bus requires at least Python 3.7+, earlier versions are not supported.

```
virtualenv venv                       # optional
source venv/bin/activate              # optional
pip install threatbus
pip install threatbus-inmem           # inmemory backbone plugin
pip install threatbus-rabbitmq        # RabbitMQ backbone plugin
pip install threatbus-misp[zmq]       # MISP application plugin
pip install threatbus-zeek            # Zeek application plugin
pip install threatbus-zmq             # ZeroMQ application plugin
pip install threatbus-<plugin_name>
```

### Testing

Use the `Makefile` to run unit and integration tests.

```
make unit-tests
make integration-tests
```

The integration tests require a local [Zeek][zeek] and
[Docker](https://www.docker.com/) installation.


## Development

Setup a virtual environment and install `threatbus` and some plugins with the
in development mode:

```
virtualenv venv
source venv/bin/activate
make dev-mode
```

### Configuration & Extension

A plugin must define a `setup.py`. Whenever a plugin is installed, you have to
add a corresponding configuration section to `threatbus`' `config.yaml`. That
section has to be named after the `name` in the entrypoint declaration of the
plugin's `setup.py` file.

Please adhere to the [plugin naming conventions](https://pluggy.readthedocs.io/en/latest/#a-complete-example)
and always prefix your plugin name with `threatbus-`.

Plugins can either be *apps* or *backbones*. Application plugins (apps) add new
functionality to Threat Bus and allow communication to a specific app and/or
via a specific protocol (e.g., ZeroMQ or Zeek/broker). Backbone plugins add a
new storage and distribution backend to Threat Bus (e.g., in-memory or
RabbitMQ).

Example:

- plugin folder structure:
  ```sh
  plugins
  ├── apps
  |   └── threatbus-myapp
  │       ├── setup.py
  |       └── threatbus_myapp.py
  └── backbones
      └── threatbus-inmem
          ├── setup.py
          └── threatbus_inmem.py
  ```
- `setup.py`
  ```py
  from setuptools import setup
  setup(
    name="threatbus-myapp",
    install_requires="threatbus",
    entry_points={"threatbus.app": ["myapp = threatbus_myapp"]},
    py_modules=["threatbus_myapp"],
  )
  ```
- `config.yaml` entry for `threatbus`
  ```yaml
  ...
  plugins:
    apps:
      myapp:
      ...
  ```

### Threat Bus API

Plugins specifications are available in `threatbus/appspecs.py` and
`threatbus/backbonespecs.py`, respectively. For any plugin, you should at least
implement the `run` function.

App plugins are provided two callback functions to use for subscription
management. Internally, Threat Bus will propagate subscription requests to all
installed backbone plugins.

The subscription callback allows applications to request an optional snapshot
time delta. Threat Bus will forward snapshot requests to all those apps that
have implemented the snapshot feature (see `threatbus/appspecs.py`).

### Implementation

Please use the
[StoppableWorker](https://github.com/tenzir/threatbus/blob/master/threatbus/stoppable_worker.py)
base class to model your plugin's busy work. Plugins should never block the main
thread of the application. Implementing that class also facilitates a graceful
shutdown.

All officially maintained Threat Bus plugins implement `StoppableWorker`. Refer
to any of the existing plugins for an example.

## License

Threat Bus comes with a [3-clause BSD license][license-url].


[opencti]: https://www.opencti.io/
[opencti-connector]: https://github.com/OpenCTI-Platform/connectors/tree/master/threatbus
[misp]: https://github.com/misp/misp
[vast]: https://github.com/tenzir/vast
[docs]: https://docs.tenzir.com/threatbus
[zeek]: https://www.zeek.org
[cif]: https://github.com/csirtgadgets/bearded-avenger
[zmq]: https://zeromq.org/
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
[plugin-types]: https://docs.tenzir.com/threatbus/plugins/overview
[plugin-development]: https://docs.tenzir.com/threatbus/plugins/plugin-development
[vast-threatbus]: https://github.com/tenzir/threatbus/tree/master/apps/vast

[pypi-badge]: https://img.shields.io/pypi/v/threatbus.svg
[pypi-url]: https://pypi.org/project/threatbus
[contributing-url]: https://github.com/tenzir/.github/blob/master/contributing.md
[latest-release-badge]: https://img.shields.io/github/commits-since/tenzir/threatbus/latest.svg?color=green
[latest-release-url]: https://github.com/tenzir/threatbus/releases
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[chat-badge]: https://img.shields.io/badge/Slack-Tenzir%20Community%20Chat-brightgreen?logo=slack&color=purple&style=flat
[chat-url]: http://slack.tenzir.com
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
[beta-badge]: https://img.shields.io/badge/stage-beta-blue
[lgtm-alerts-badge]: https://img.shields.io/lgtm/alerts/g/tenzir/threatbus.svg?logo=lgtm&logoWidth=18
[lgtm-alerts-url]: https://lgtm.com/projects/g/tenzir/threatbus/alerts/
[lgtm-quality-badge]: https://img.shields.io/lgtm/grade/python/g/tenzir/threatbus.svg?logo=lgtm&logoWidth=18
[lgtm-quality-url]: https://lgtm.com/projects/g/tenzir/threatbus/context:python
