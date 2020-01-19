Threat Bus MISP Plugin
======================

A Threat Bus plugin that enables communication to [MISP](https://www.misp-project.org/).

## Installation

```sh
pip install threatbus-misp
```

## Development Setup

Use the DCSO's [dockerized MISP](https://github.com/DCSO/MISP-dockerized) to set up a local testing environment:

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

*Restart all MISP services that changed*

```sh
make deploy
```

*Enable the ZMQ plugin in the MISP webview*

- Visit localhost:80
- login with your configured credentials
- Go to `Administration` -> `Server Settings & Maintenance` -> `Diagnostics Tab`
- Find the ZeroMQ plugin section and enable it
- Go to `Administration` -> `Server Settings & Maintenance` -> `Plugin settings Tab`
- Set the entry `Plugin.ZeroMQ_attribute_notifications_enable` to `true`