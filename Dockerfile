FROM debian:bullseye

RUN apt-get -qq update && apt-get -qqy install \
  python3-pip software-properties-common gnupg2 libbroker2 python3-broker

RUN pip3 install --upgrade pip

EXPOSE 47761 13370 13371 13372

WORKDIR /opt/tenzir/threatbus
COPY setup.py .
COPY README.md .
COPY threatbus threatbus
COPY plugins plugins
RUN python3 -m pip install . && \
  python3 -m pip install plugins/apps/threatbus_cif3 && \
  python3 -m pip install plugins/apps/threatbus_misp[zmq] && \
  python3 -m pip install plugins/apps/threatbus_zeek && \
  python3 -m pip install plugins/apps/threatbus_zmq && \
  python3 -m pip install plugins/backbones/threatbus_inmem && \
  python3 -m pip install plugins/backbones/threatbus_rabbitmq
COPY config* ./

ENTRYPOINT ["threatbus"]
