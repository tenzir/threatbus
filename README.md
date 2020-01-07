
<h1 align="center">
  Threat-Bus
</h1>
<h4 align="center">

The missing tool to interconnect open-source security applications.

[![Build Status][ci-badge]][ci-url]
[![Latest Release][latest-release-badge]][latest-release-url]
[![License][license-badge]][license-url]

[_Getting Started_](#getting-started) &mdash;
[_Contributing Guidelines_][contributing-url] &mdash;
[_Writing Plugins_](#Writing-plugins) &mdash;
[_Changelog_][changelog-url] &mdash;
[_License_](#license)

</h4>

**Threat-Bus** (`threat-bus`) connects various open-source security applications
and facilitates data exchange. With Threat-Bus your can seamlessly integrate
MISP intelligence with the Zeek intel framework or report sightings from IDS
deployments to some data base.

The project is plugin-based and can be extended easily.


## Plugin Development

Setup a virtual environment and install threat-bus and some plugins:
```
virtualenv venv
source venv/bin/activate
pip install --editable .
pip install --editable plugins/backbones/threatbus-inmem
pip install --editable plugins/<desired-plugins>
```

### Configuration & Extension

A plugin must define a `setup.py`. Whenever a plugin is installed, you have to
add a corresponding configuration section to threat-bus' `config.yaml`. That
section has to be named after the `name` in the entrypoint declaration of the
plugin's `setup.py` file.

Please adhere to the [plugin naming conventions](https://pluggy.readthedocs.io/en/latest/#a-complete-example)
and always prefix your plugin name with `threatbus-`.

Plugins can either be *apps* or *backbones*. Application plugins (apps) add new
functionality to `threat-bus` and allow communication to a
threat-intelligence-enabled app (e.g., Zeek or Suricata). Backbone plugins add a
new storage and distribution backend to `threat-bus` (e.g., in-memory or Kafka).

Example:

- plugin folder structure:
  ```sh
  plugins
  ├── apps
  │   └── threatbus-zeek
  │       ├── setup.py
  │       └── threatbus_zeek.py
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
- `config.yaml` entry for `threat-bus`
  ```yaml
  ...
  plugins:
    apps:
      myapp:
      ...
  ```

## License

Threat-Bus comes with a [3-clause BSD license][license-url].


[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[zeek]: https://www.zeek.org
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration

[contributing-url]: https://github.com/tenzir/.github/blob/master/contributing.md
[latest-release-badge]: https://img.shields.io/github/commits-since/tenzir/threat-bus/latest.svg?color=green
[latest-release-url]: https://github.com/tenzir/threat-bus/releases
[ci-url]: https://github.com/tenzir/threat-bus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threat-bus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threat-bus/blob/master/COPYING