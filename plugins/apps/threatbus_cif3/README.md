Threat Bus CIFv3 Plugin
======================

A Threat Bus plugin that enables communication to [Collective Intelligence Framework v3](https://github.com/csirtgadgets/bearded-avenger).

## Installation

```sh
pip install threatbus-cif3
```

## Configuration

The plugin uses the cifsdk python client to submit indicators received on the threatbus into a CIF instance.

```yaml
...
plugins:
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

### Dockerized CIFv3

Use [dockerized CIFv3](https://github.com/sfinlon/cif-docker) to set
up a local CIFv3 environment:

*Setup a CIFv3 docker container*

```sh
git clone https://github.com/sfinlon/cif-docker.git
cd cif-docker
docker-compose build
```

*Edit the docker-compose.yml*

```sh
vim docker-compose.yml
```
Find the section `cif` in the configuration and edit the following as appropriate:

```yaml
cif:
    ...
    ports:
      - "5000:5000"
    ...
```


*Start the container*

```sh
docker-compose up -d
# get an interactive shell
docker-compose exec cif /bin/bash
# become the cif user
su cif
# check to see if access tokens were successfully created
cif-tokens
# ping the router to ensure connectivity
cif --ping
```

## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-misp.svg
[pypi-url]: https://pypi.org/project/threatbus-misp
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
