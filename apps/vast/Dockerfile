ARG VAST_VERSION=latest

FROM tenzir/vast:$VAST_VERSION
USER root

RUN apt-get -qq update && apt-get -qqy install \
  python3-pip software-properties-common

RUN pip3 install --upgrade pip

WORKDIR /opt/tenzir/threatbus/pyvast-threatbus
COPY setup.py .
COPY README.md .
COPY pyvast_threatbus pyvast_threatbus
RUN python3 -m pip install .
COPY config.yaml.example config.yaml

ENTRYPOINT ["pyvast-threatbus"]
CMD ["-c", "config.yaml"]
