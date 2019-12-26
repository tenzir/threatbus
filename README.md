# Threat-Bus

The **Threat-Bus** (`threat-bus`) autonomously performs routine task of an
incident response team. The project is plugin-based and can be easily extended.

## Development Installation

```
virtualenv venv
source venv/bin/activate
pip install --editable .
pip install --editable plugins/backbones/threatbus-inmem
pip install --editable plugins/<desired-plugins>
```

## Plugin Configuration & Extension

A plugin must define a `setup.py`. Whenever a plugin is installed, you have to add a corresponding configuration section to threat-bus's `config.yaml`. That section has to be named after the `name` in the entrypoint declaration of the plugin's `setup.py` file.

Please adhere to the [plugin naming conventions](https://pluggy.readthedocs.io/en/latest/#a-complete-example) and always prefix your plugin name with `threatbus-`.

Plugins can either be application plugins or backbones. Application plugins add new functionality to `threat-bus` and allow communication to a threat-intelligence app (e.g., Zeek or Suricata). Backbones plugins add a new storage & distribution backend to `threat-bus` (e.g., in-memory or Kafka).

Example:

- plugin folder structure:
  ```sh
  plugins
  ├── apps
  │   └── threatbus-zeek
  │       ├── setup.py
  │       └── threatbus_zeek.py
  └── backbones
      └── threatbus-inmem
          ├── setup.py
          └── threatbus_inmem.py
  ```
- `setup.py`
  ```py
  from setuptools import setup
  setup(
    name="threatbus-myapp",
    install_requires="threatbus",
    entry_points={"threatbus.app": ["myapp = threatbus_myapp"]},
    py_modules=["threatbus_myapp"],
  )
  ```
- `config.yaml` entry for `threat-bus`
  ```yaml
  ...
  plugins:
    apps:
      myapp:
      ...
  ```

## License

Copyright (c) Tenzir GmbH
All rights reserved.

[misp]: https://github.com/misp/misp
[vast]: https://github.com/vast-io/vast
[broker]: https://github.com/zeek/broker
[tenzir]: https://docs.tenzir.com
[zeek]: https://www.zeek.org
[misp-zmq-config]: https://github.com/MISP/misp-book/tree/master/misp-zmq#misp-zeromq-configuration
