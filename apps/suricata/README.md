Suricata Threat Bus App
=======================

Threat Bus is a publish-subscribe broker for threat intelligence. It is expected
that applications register themselves at the bus. Since Suricata can't do that
on it's own (yet) this app works as a bridge application in the meantime.

It receives indicators from Threat Bus and picks up all those where the STIX-2
`pattern_type` equals `"suricata"`. The suricata rules from those IoCs are then
forwarded to Suricata using a pre-configured rules file and then reloaded via
[suricatasc](https://suricata.readthedocs.io/en/latest/manpages/suricatasc.html).

Make sure to run this app on the same host as your Suricata installation.
Make also sure that this app (e.g., user running this app) has the correct
permissions to use the `suricatasc` command line utility and can read/write the
rules file.

Received rule updates are not applied instantaneously to minimize load on
Suricata. Instead, users must configure the `reload_interval` (seconds) in the
config file to enable periodic reloads for Suricata to pick up rule changes.

## Quick Start

You can configure the app via a YAML configuration file. See
`config.yaml.example` for an example config file. Rename the example to
`config.yaml` before starting.

Alternatively, configure the app via environment variables, similarly to Threat
Bus, or pass a path to configuration file via `-c /path/to/config.yaml`.

Install `suricata-threatbus` in a virtualenv and start:

```sh
python -m venv venv
source venv/bin/activate
make dev-mode
suricata-threatbus
```

You first need to configure the `rules_file` option in the config file. See also
below for configuring your local Suricata installation to work with this app.

### Suricata Preparation

This app maintains a file with Suricata rules. The app writes to it and Suricata
reads from it. You need to make this file known to your Suricata installation by
adding it to the rules configuration section in the `suricata.yaml` config file.
Suricata won't pick up rule changes if you skip this step.

Here is an example snippet to add to your Suricata config file:

```
/etc/suricata/suricata.yaml
--------------------------------------------------------------------------------

....

default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - threatbus.rules         # !! managed by suricata-threatbus

....
```

In this example, we configure Suricata to read additional rules from a file
called `threatbus.rules`, located in the default rule path
`/var/lib/suricata/rules`.

You need to provide the path of your custom rule file to this app, so it can
modify the file contents when new indicators arrive. See also the `rules_file`
config option in the `config.yaml.example` file.
