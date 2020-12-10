Threat Bus Systemd Unit
=======================

This folder provides `systemd` service units to run Threat Bus and
`pyvast-threatbus` as system services. The services are sandboxed and run with
limited privileges.

## Prepare the Host System

The systemd unit declares a private user. Hence, all logs go to
`/var/log/private` by default. The following section explains how to configure
file-logging for Threat Bus and `pyvast-threatbus`. Skip the following
instructions if you configure your applications to use console-logging.

Find the `logging` config section at the top of your Threat Bus or
`pyvast-threatbus` configuration file and change it to use the private log
directory:

- `/var/log/private/threatbus/threatbus.log` (Threat Bus)
- `/var/log/private/pyvast-threatbus/pyvast-threatbus.log` (`pyvast-threatbus`)

See the following YAML snippet for a configuration example.

```yaml
logging:
  console: false
  console_verbosity: INFO
  file: true
  file_verbosity: DEBUG
  filename: /var/log/private/threatbus/threatbus.log
```

## Usage

Before you begin, find the line beginning with `ExecStart=` at the very bottom
of the `[Service]` section in the unit file. Depending on your installation path
you might need to change the location of the `threatbus` and `pyvast-threatbus`
executable packages and configuration files. Similarly, you need to change the
environmentvariables `THREATBUSDIR` and `PYVAST_THREATBUSDIR` according to your
installation paths.

- Threat Bus
  ```bash
  Environment="THREATBUSDIR=/installation/path"
  ExecStart=/installation/path/threatbus --config=/installation/path/threatbus/config.yaml
  ```

- `pyvast-threabus`
  ```bash
  Environment="PYVAST_THREATBUSDIR=/installation/path"
  ExecStart=/installation/path/pyvast-threatbus --config=/installation/path/pyvast-threatbus/config.yaml
  ```

Then copy (or symlink) the unit file to `/etc/systemd/system`.

```bash
systemctl link "$PWD/threatbus.service"
systemctl link "$PWD/pyvast-threatbus.service"
```

To have the services start up automatically with system boot, you can `enable`
them via `systemd`. Otherwise, just `start` it to run it immediately.

```bash
systemctl enable threatbus
systemctl start threatbus
systemctl enable pyvast-threatbus
systemctl start pyvast-threatbus
```
