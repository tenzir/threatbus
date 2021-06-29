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
WORKDIR /opt/tenzir/threatbus/stix-shifter-threatbus
COPY apps/stix-shifter/setup.py .
COPY apps/stix-shifter/README.md .
COPY apps/stix-shifter/stix_shifter_threatbus stix_shifter_threatbus
RUN python3 -m pip install .

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["stix-shifter-threatbus"]
