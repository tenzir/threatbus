# This is a clone of the open-source Dockerfile for pyvast-threatbus,
# but based on the closed-source VAST Dockerfile instead so we can
# use the matcher plugin.

FROM vast-pinned:${EVENT_HORIZON_VERSION:-latest}
USER root

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
WORKDIR /opt/tenzir/threatbus/pyvast-threatbus
COPY apps/vast/setup.py .
COPY apps/vast/README.md .
COPY apps/vast/pyvast_threatbus pyvast_threatbus
RUN python3 -m pip install .

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["pyvast-threatbus"]
