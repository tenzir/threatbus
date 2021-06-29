FROM debian:buster-slim

RUN apt-get -qq update && apt-get -qqy install \
  python3-pip software-properties-common

RUN pip3 install --upgrade pip

# Install Threat Bus to have it as `latest` dependency when building the app.
WORKDIR /opt/tenzir/threatbus
COPY setup.py .
COPY README.md .
COPY threatbus threatbus
RUN python3 -m pip install .

# Install the app.
WORKDIR /opt/tenzir/threatbus/suricata-threatbus
COPY apps/suricata/setup.py .
COPY apps/suricata/README.md .
COPY apps/suricata/suricata_threatbus suricata_threatbus
RUN python3 -m pip install .

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["suricata-threatbus"]
