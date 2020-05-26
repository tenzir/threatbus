Threat Bus CIFv3 Plugin
======================

A Threat Bus plugin that enables communication to [Collective Intelligence Framework v3](https://github.com/csirtgadgets/bearded-avenger).

## Installation

```sh
pip install threatbus-cif3
```

## Configuration

The plugin uses the cifsdk python client to report back MISP indicators.

```yaml
...
plugins:
  misp:
    api:
      host: https://misp.host.tld
      ssl: false
      key: MISP_API_KEY
    zmq:
      host: misp.host.tld
      port: 50000
  cif3:
    api:
      host: http://cif.host.tld:5000
      ssl: false
      token: CIF_TOKEN
    group: everyone
    confidence: 7.5
    tlp: amber
    tags:
      - test
      - malicious
...
```

## Development Setup

The following guides describe how to set up local, dockerized instances of MISP.

### Dockerized MISP

Use DCSO's [dockerized MISP](https://github.com/DCSO/MISP-dockerized) to set
up a local testing environment:

*Setup a MISP Docker cluster*

```
git clone git@github.com:DCSO/MISP-dockerized.git
cd MISP-dockerized
make install
# follow the dialog...
```

*Edit the docker-compose.yaml*

```sh
cd current
vim docker-compose.yaml
```
Find the section `misp-server` in the configuration and add the following:

```yaml
misp-server:
    ...
    ports:
      - "50000:50000"
    ...
```


*Restart MISP to accept the new port*

```sh
make deploy
```

*Enable the ZMQ plugin in the MISP webview*

- Visit https://localhost:80
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Diagnostics Tab`
- Find the ZeroMQ plugin section and enable it
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the entry `Plugin.ZeroMQ_attribute_notifications_enable` to `true`

*Restart all MISP services*

```sh
make restart-all
```


## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-misp.svg
[pypi-url]: https://pypi.org/project/threatbus-misp
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
