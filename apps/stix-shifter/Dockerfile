FROM debian:buster-slim

RUN apt-get -qq update && apt-get -qqy install \
  python3-pip software-properties-common

RUN pip3 install --upgrade pip

WORKDIR /opt/tenzir/threatbus/stix-shifter-threatbus
COPY setup.py .
COPY README.md .
COPY stix_shifter_threatbus stix_shifter_threatbus
RUN python3 -m pip install .

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["stix-shifter-threatbus"]
CMD ["-h"]
