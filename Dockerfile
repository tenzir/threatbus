FROM fixel/zeek:broker-latest

RUN apt-get update -qqy && apt-get install -qqy python3-pip
RUN pip3 install --upgrade pip

EXPOSE 47761

WORKDIR /opt/tenzir/threatbus
COPY setup.py .
COPY README.md .
COPY threatbus threatbus
COPY plugins plugins
RUN pip install . && \
  pip install plugins/apps/threatbus-zeek && \
  pip install plugins/backbones/threatbus-inmem
COPY config* ./

ENTRYPOINT ["threatbus"]
CMD ["-c", , "config.yaml"]