Threat Bus RabbitMQ Backbone Plugin
===================================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin to use RabbitMQ as message broker backbone.

## Installation

```sh
pip install threatbus-rabbitmq
```

## Configuration

The plugin requires a RabbitMQ endpoint to start.

```yaml
...
plugins:
  backbones:
    rabbitmq:
      host: localhost
      port: 5672
...
```


## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-rabbitmq.svg
[pypi-url]: https://pypi.org/project/threatbus-rabbitmq
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
