Threat Bus RabbitMQ Backbone Plugin
===================================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A Threat Bus plugin to use RabbitMQ as message broker backbone.

### RabbitMQ Properties

The plugin declares one fanout exchange with a configurable name and binds a
single queue to it. Messages are all routed via that exchange. Multiple Threat
Bus instances can bind to it, but per convention must use unique queue names.
The queue name will be `threatbus.<hostname>` where `<hostname>` is the
hostname of the machine running Threat Bus. You can overwrite this behavior in
the configuration file.

Messages sent over RabbitMQ are all serialized JSON. Each object must specify a
`type` field. Serialization, e.g., to STIX-2 objects or to Threat Bus internal
data types, is implemented based on the `type` field.

### Subscriptions

Application plugins can subscribe to topics and topic prefixes.

## Installation

```sh
pip install threatbus-rabbitmq
```

## Configuration

The plugin requires a RabbitMQ endpoint to start. You can configure endpoint
details in the plugin configuration of the Threat Bus `config.yaml`. You can
fine-tune resource behavior with the `queue` section of the config. 

```yaml
...
plugins:
  backbones:
    rabbitmq:
      host: localhost
      port: 5672
      username: guest
      password: guest
      vhost: /
      exchange_name: threatbus
      queue:
        name_suffix: "my_suffix" # this defaults to 'hostname' if left blank
        name_join_symbol: . # queue will be named "threatbus" + join_symbol + name_suffix
        durable: true
        auto_delete: false
        lazy: true
        exclusive: false
        max_items: 100000 # optional. remove property / set to 0 to allow infinite length
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
