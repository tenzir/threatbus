Threat Bus Zeek Plugin
======================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin that enables communication to [Zeek](https://zeek.org/).

## Installation

```sh
pip install threatbus-zeek
```

#### Prerequisites

*Install [Broker](https://github.com/zeek/broker) on the Threat Bus host*

The plugin uses the [Broker python bindings](https://docs.zeek.org/projects/broker/en/stable/python.html)
to enable communication with Zeek. You have to install Broker and bindings to
use this plugin.

## Configuration

The plugin starts a listening Broker endpoint. The endpoint characteristics for
listening can be cofigure as follows:

```yaml
...
plugins:
  apps:
    zeek:
      host: "127.0.0.1"
      port: 47761
      module_namespace: Tenzir
...
```

## Threat Bus Zeek Script

Threat Bus is a pub/sub broker for threat intelligence data. Applications, like
Zeek, have to register themselves at the bus. Hence, load this [Zeek script](https://github.com/tenzir/threatbus/blob/master/apps/zeek/threatbus.zeek)
into your Zeek installation to make it aware of Threat Bus.

The script can be configured via certain `option`s for setting topic names or
requesting an intel snapshot:

```sh
zeek -i <INTERFACE> -C ./apps/zeek/threatbus.zeek -- "Tenzir::snapshot_intel=-30 days"
```

## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-zeek.svg
[pypi-url]: https://pypi.org/project/threatbus-zeek
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING