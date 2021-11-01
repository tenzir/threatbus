Template for Apps that connect via ZeroMQ
=========================================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. This template provides a basic
`async` Python application that can (un)subsscribe to/from Threat Bus via
ZeroMQ. To connect via ZeroMQ, users must install and configure the
[`threatbus-zmq`](https://pypi.org/project/threatbus-zmq/) plugin on
their Threat Bus host.

## Quick Start

You can configure the app via a YAML configuration file. See
`config.yaml.example` for an example config file. Rename the example to
`config.yaml` before starting.

Alternatively, configure the app via environment variables, similarly to Threat
Bus, or pass a path to configuration file via `-c /path/to/config.yaml`.

Install the template in a virtualenv and start it with a config file:

```sh
make install
poetry shell
```
