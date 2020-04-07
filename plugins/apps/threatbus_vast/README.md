Threat Bus VAST Plugin
======================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin that enables communication to [VAST](https://github.com/tenzir/vast).


## Installation

```sh
pip install threatbus-vast
```

## Configuration

The plugin uses ZeroMQ to communicate with the
[VAST bridge](https://github.com/tenzir/threatbus/tree/master/apps/vast). The
plugin serves as a Zmq endpoint for the bridge to connect with. It uses three
endpoints. One for managing subscriptions (and thus snapshot requests). The
other two endpoints are for plain pub-sub.

```yaml
...
plugins:
  vast:
    host: "127.0.0.1"
        manage: 13370
        pub: 13371
        sub: 13372
...
```

Initially, the bridge only needs to know the `manage` endpoint. The plugin and
the vast-bridge negotiate all other internals for pub-sub message exchange at
runtime.

## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-vast.svg
[pypi-url]: https://pypi.org/project/threatbus-vast
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING