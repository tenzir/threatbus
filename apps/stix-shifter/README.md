STIX-Shifter Threat Bus
=======================

This app bridges the gap between Threat Bus and various security tools by
leveraging
[STIX-Shifter](https://github.com/opencybersecurityalliance/stix-shifter).

STIX-Shifter is a tool and library to transform STIX patterns into native
queries for a variety of (mostly commercial) security tools, like
[IBM QRadar](https://www.ibm.com/security/security-intelligence/qradar) or
[Splunk](https://www.splunk.com/). This app connects STIX-Shifter with Threat
Bus and provides a simple way to communicate with the commercial tools of your
choice via Threat Bus.

## How It Works

The `stix-shifter-threatbus` app uses ZeroMQ to connect with Threat Bus. To
connect via ZeroMQ, users must first install and configure the
[`threatbus-zmq`](https://pypi.org/project/threatbus-zmq/) plugin on
their Threat Bus host.

This app functions as middleman between Threat Bus and security tools supported
by STIX-Shifter. It subscribes to indicator updates from the bus and uses
STIX-Shifter to actively translate STIX-2 intelligence to native queries.
The app then executes these queries via STIX-Shifter. [Result processing
is yet to be implemented.]

## Quick Start

You can configure the app via a YAML configuration file or via env vars. See
`config.yaml.example` for an example config file. Rename the example to
`config.yaml` before starting.

Alternatively, configure the app via environment variables, similarly to Threat
Bus, or pass a path to configuration file via `-c /path/to/config.yaml`.

Install `stix-shifter-threatbus` in a virtualenv and start it:

```sh
python -m venv venv
source venv/bin/activate
make dev-mode
stix-shifter-threatbus
```

### Docker

You can also run this app via Docker.

- Build it:
  ```
  docker build . -t tenzir/stix-shifter-threatbus:latest
  ```
- Run it to print the helptext.
  ```
  docker run tenzir/stix-shifter-threatbus:latest
  ```
- Run and mount a custom config file into the container:
  ```
  docker run --net=host -v /path/to/your/conf.yaml:/opt/tenzir/threatbus/stix-shifter-threatbus/config.yaml tenzir/stix-shifter-threatbus:latest -c config.yaml
  ```

## Configuration

Apart from the logging section, which is self-explanatory, users need to
configure the `threatbus` endpoint of the ZerMQ-App plugin and an optional
`snapshot` of historic threat intel data they want to fetch.

Additionally, users must configure each STIX-Shifter module individually to use
it with this app. You also must install the corresponding modules according to
your configuration. For example, if you configure a key `splunk` in the
`modules` section, you must install the `stix-shifter-modules-splunk`. Otherwise
the app will throw an error. See below for an example:

```
threatbus: localhost:13370 # connect with Threat Bus via this endpoint
snapshot: 300 # request 300 days of historic indicators
modules:
  # for details on a module's options, please see https://github.com/opencybersecurityalliance/stix-shifter/blob/master/OVERVIEW.md#how-to-use
  # to use the key `splunk` you must install `stix-shifter-modules-splunk`
  # same goes for any other key, e.g., `elastic`, `qradar`, etc...
  splunk:
    max_results: 100 # limit the number of events queried by STIX-Shifter
    # https://github.com/opencybersecurityalliance/stix-shifter/blob/master/OVERVIEW.md#connection
    connection:
      host: localhost
      port: 8089 # Management port
      selfSignedCert: false
    # https://github.com/opencybersecurityalliance/stix-shifter/blob/master/OVERVIEW.md#configuration
    transmission:
      auth:
        username: admin
        password: admin123
    # https://github.com/opencybersecurityalliance/stix-shifter/blob/master/OVERVIEW.md#translate
    translation: # {<Any required options specific to the particular data source>}
    # The data_source is a STIX-2 DataSource (e.g., an `identity`) and is used
    # to create a STIX bundle with the queried results. You configure it here
    # and only once for this module.
    data_source:
      type: identity
      identity_class: events
      name: Splunk
      id: identity--629a6400-8817-4bcb-aee7-8c74fc57482c
```
