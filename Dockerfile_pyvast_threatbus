# The used version here always refers to the latest released VAST version.
# Use `latest` to get the most recent version of VAST as it is available on the
# Git master branch at https://github.com/tenzir/vast.
ARG VAST_VERSION=2021.06.24

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

RUN echo "Adding threatbus user" && useradd -m -d /home/threatbus --user-group threatbus
RUN chown -R threatbus .
USER threatbus:threatbus

ENTRYPOINT ["pyvast-threatbus"]
