FROM debian:buster-slim

RUN apt-get -qq update && apt-get -qqy install \
  python3-pip software-properties-common

RUN pip3 install --upgrade pip

WORKDIR /opt/tenzir/threatbus/suricata-threatbus
COPY setup.py .
COPY README.md .
COPY suricata_threatbus suricata_threatbus
RUN python3 -m pip install .

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["suricata-threatbus"]
CMD ["-h"]
