Threat Bus to VAST Bridge
=========================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since VAST cannot do so on its
own (yet), `vast-bridge.py` implements that functionality in the meantime.

The bridge provides a thin layer around 
[PyVAST](https://docs.tenzir.com/vast/python-bindings/overview), VAST's Python
CLI bindings. It facilitates message exchange between Threat Bus and a VAST
instance.

## Setup

- Install the `requirements.txt` for the VAST wrapper script

```sh
virtualenv --system-site-packages venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Quick Start

The bridge is configured either via a config file in YAML format or via command
line arguments and flags. See `config.yaml.example` for an example configuration
file that make use of [fever alertify](https://github.com/DCSO/fever) to
transform sighting contexts before they get printed to `STDOUT`. See the section
[Bridge Features](/tenzir/threatbus/tree/master/apps/vast#bridge-features) for
details. Or inspect the command help as follows.

```sh
./vast-bridge.py --help
```

Start with a config file.

```sh
./vast-bridge.py -c config.yaml
```

Startup with debug logging and customized endpoints for Threat Bus and VAST.

```sh
./vast-bridge.py --vast-binary=/opt/tenzir/bin/vast --vast=localhost:42000 --threatbus=localhost:13370 --loglevel=DEBUG
```

Request an intelligence snapshot of the past 50 days and match it
retrospectively against the entire VAST database.

```sh
./vast-bridge.py --snapshot=50 --retro-match
```

## Bridge Features

This section explains the most important features and CLI options of the
`vast-bridge`.

### IoC Matching

[VAST](https://github.com/tenzir/vast) can match IoCs either live or
retrospectively via usual queries.

#### Live Matching

VAST's
[live matching](https://docs.tenzir.com/vast/features/threat-intel-matching)
works as
[continuous query](https://docs.tenzir.com/vast/cli/vast/export/#documentation).
The `vast-bridge` subscribes to those continuous query results and reports all
new IoC matches from VAST to Threat Bus as `Sightings`.

Live matching is the default mode of operation for the `vast-bridge`. Note
that the VAST node must support this feature.

#### Retro Matching

The `vast-bridge` supports retro matching via the command line option
`--retro-match`. This instructs the bridge to translate IoCs from
Threat Bus to normal VAST queries instead of feeding the IoCs to a live matcher.

Each result from an IoC query is treated as `Sighting` of that IoC and reported
back to Threat Bus.

### Sighting Context Transformation

The bridge provides a command line option to invoke another program for parsing
Sighting `context` data.

The option `--transform-context "cmd args"` translates the `context`
field of a Sighting via the specified utility. For example, pass the `context`
object to [DCSO/fever](https://github.com/DCSO/fever) `alertify`:

```
apps/vast/vast-bridge.py --retro-match --transform-context "fever alertify --alert-prefix 'MY PREFIX' --extra-key my-ioc --ioc %ioc"
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

Note that the `cmd` string passed to `--transform-context` is treated as
template string. The placeholder `%ioc` is replaced with the contents of the
actually matched IoC.

### Custom Sinks for Sightings

The `vast-bridge` offers to send Sighting `context` to a configurable `sink`
_instead_ of reporting them back to Threat Bus. This can be configured via the
`--sink` parameter. The special placeholder `STDOUT` can be used to print the
Sighting context to `STDOUT`. Example:

```
./vast-bridge.py --sink stdout
```

A custom sink is useful to forward `Sightings` to another process, like
`syslog`, or forward STDOUT via a UNIX pipe. Note that it may be desirable to
disable logging in that case (`--loglevel NOTSET`).

Note that only the `context` field is printed, and not the object structure of
the `Sighting`. The `Sighting` itself is a Threat Bus internal format and most
likely not usable for most applications.
