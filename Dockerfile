FROM fixel/zeek:broker-latest

RUN apt-get update -qqy && apt-get install -qqy python3-pip
RUN pip3 install --upgrade pip

EXPOSE 47761

WORKDIR /opt/tenzir/threatbus
COPY setup.py .
COPY README.md .
COPY threatbus threatbus
COPY plugins plugins
RUN python3 setup.py install && \
  python3 plugins/apps/threatbus_zeek/setup.py install && \
  python3 plugins/backbones/threatbus_inmem/setup.py install
COPY config* ./

ENTRYPOINT ["threatbus"]
CMD ["-c", , "config.yaml"]