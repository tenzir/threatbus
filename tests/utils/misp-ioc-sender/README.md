# MISP IoC Sender

A script to trigger an Attribute update in MISP. The script is configured via a
YAML file. See below for details and check out the `config.yaml.example` file.

The script works as follows:

- Look for a specific MISP Event, referenced by its UUID in the config file.
- Create the Event if it doesn't exist.
- Check the Attributes of the Event and either create a new Attribute or toggle
  the `'to_ids'` flag if the Attribute already exists.
- If configured, additionally report a sighting for the attribute.

Attributes created by this script always have the `"DOMAIN"` type. Attribute
values contain the current day of the year and are always formatted like this:
`test-%YYYY-%mm-%dd.vast`.

## Configuration

The `config.yaml` file consists of 3 blocks:

- Logging configuration
- MISP endpoint configuration
- The MISP Event UUID

See the `config.yaml.example` file to get started.


## Usage

First, install the `requirements.txt` via `pip`. Then run the script and pass
the configuration file to it via the `-c` command line option.

```
pip install -r requirements.txt
python misp-ioc-sender.py -c config.yaml
```
