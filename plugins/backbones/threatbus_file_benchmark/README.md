Threat Bus In-Memory Backbone Plugin
====================================

<h4 align="center">

[![PyPI Status][pypi-badge]][pypi-url]
[![Build Status][ci-badge]][ci-url]
[![License][license-badge]][license-url]

</h4>

A very simplistic Threat Bus plugin that is used for internal benchmarking. The
backbone does not multiplex messages. Instead, it reads a file and sends the
file contents in form of new messages to the subscribed app plugins.

## Installation

This plugin is not published on PyPI. It is only used for testing. Run it
directly from source.

```
pip install --editable .
```

## Usage & Configuration

You need to configure a line-delimited JSON file as input. The plugin accepts
valid STIX-2 JSON (only STIX-2 `Indicators` and `Sightings`).

It reads all lines from the configured file and sends them to all configured app
plugins. You can configure a `repetitions` parameter, to send the file contents
more than once.

```yaml
...
plugins:
  backbones:
    file_benchmark:
      input_file: bench.json
      repetitions: 10
...
```

## License

Threat Bus comes with a [3-clause BSD license][license-url].

[pypi-badge]: https://img.shields.io/pypi/v/threatbus-inmem.svg
[pypi-url]: https://pypi.org/project/threatbus-inmem
[ci-url]: https://github.com/tenzir/threatbus/actions?query=branch%3Amaster
[ci-badge]: https://github.com/tenzir/threatbus/workflows/Python%20Egg/badge.svg?branch=master
[license-badge]: https://img.shields.io/badge/license-BSD-blue.svg
[license-url]: https://github.com/tenzir/threatbus/blob/master/COPYING
