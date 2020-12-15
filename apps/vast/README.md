PyVAST Threat Bus App
=====================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since VAST cannot do so on its
own (yet), `pyvast-threatbus.py` implements that functionality in the meantime.

The application provides a thin layer around
[PyVAST](https://docs.tenzir.com/vast/python-bindings/overview), VAST's Python
CLI bindings. It facilitates message exchange between Threat Bus and a VAST
instance.

## Installation

Install `pyvast-threatbus` via `pip`. Optionally, use a virtual environment.

```
virtualenv venv           # optional
source venv/bin/activate  # optional
python -m pip install pyvast-threatbus
```

## Development

Use the `dev-mode` command from the `Makefile` to install the project in
[development mode](https://setuptools.readthedocs.io/en/latest/userguide/development_mode.html).
We recommend to use a virtual environment for development.

```
virtualenv venv
source venv/bin/activate
make dev-mode
```

## Quick Start

You can configure the app via a YAML configuration file. See
`config.yaml.example` for an example config file that uses
[fever alertify](https://github.com/DCSO/fever) to transform sighting contexts
before they get printed to `STDOUT`. See the section
[Features](/tenzir/threatbus/tree/master/apps/vast#features) for details.

Start the application with a config file:

```sh
./pyvast_threatbus.py -c config.yaml
```

## Features

This section explains the most important features of `pyvast-threatbus`.

### IoC Matching

[VAST](https://github.com/tenzir/vast) can match IoCs either live or
retrospectively via usual queries.

#### Live Matching

VAST's
[live matching](https://docs.tenzir.com/vast/features/threat-intel-matching)
works as
[continuous query](https://docs.tenzir.com/vast/cli/vast/export/#documentation).
`pyvast-threatbus` subscribes to those continuous query results and reports all
new IoC matches from VAST to Threat Bus as `Sightings`.

Live matching is the default mode of operation for `pyvast-threatbus`. Note that
the VAST node must support this feature.

#### Retro Matching

`pyvast-threatbus` supports retro matching. You can enable it in the config file
by setting `retro_match: true`. This instructs the application to translate IoCs
from Threat Bus to normal VAST queries instead of feeding the IoCs to a live
matcher.

Each result from an IoC query is treated as `Sighting` of that IoC and reported
back to Threat Bus. You can limit the maximum amount of results returned from
VAST by setting the config option `retro_match_max_events` to a positive integer.

### Sighting Context Transformation

You can configure `pyvast-threatbus` to invoke another program for parsing
Sighting `context` data via the config option `transform_context`.

If set, the app translates the `context` field of a Sighting via the specified
utility. For example, configure the app to pass the `context`
object to [DCSO/fever](https://github.com/DCSO/fever) `alertify`:

```yaml
...
transform_context: fever alertify --alert-prefix 'MY PREFIX' --extra-key my-ioc --ioc %ioc
...
```

A `Sighting` object is structured as follows:

```yaml
{
  "ts": "2020-09-04 11:21:13.663164",
  "reference": "threatbus__86",
  "ioc": "foobar.com",
  "context": {
    ...
  }
```

The `context` field can contain arbitrary data. For example, retro matches from
VAST contain the full query result in the context field (like a Suricata EVE
entry or a Zeek conn.log entry).

Note that the `cmd` string passed to `transform_context` is treated as
template string. The placeholder `%ioc` is replaced with the contents of the
actually matched IoC.

### Custom Sinks for Sightings

`pyvast-threatbus` offers to send Sighting `context` to a configurable `sink`
_instead_ of reporting them back to Threat Bus. This can be configured via the
`sink` configuration parameter. The special placeholder `STDOUT` can be used to
print the Sighting context to `STDOUT`.

A custom sink is useful to forward `Sightings` to another process, like
`syslog`, or forward STDOUT via a UNIX pipe. Note that it may be desirable to
disable logging in that case.

Note that only the `context` field is printed, and not the object structure of
the `Sighting`. The `Sighting` itself is a Threat Bus internal format and most
likely not usable for most applications.
