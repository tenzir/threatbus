Threat Bus In-Memory Backbone Plugin
====================================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A very simplistic Threat Bus plugin that provides an in-memory backbone for data
provisioning.

## Installation

```sh
pip install threatbus-inmem
```

## Configuration

Add a placeholder for this plugin's config:

```yaml
...
plugins:
  backbones:
    inmem:
...
```

There is no further configuration needed.


## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-inmem.svg
[pypi-url]: https://pypi.org/project/threatbus-inmem
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING