# The used version here always refers to the latest released VAST version.
# Use `latest` to get the most recent version of VAST as it is available on the
# Git master branch at https://github.com/tenzir/vast.
ARG VAST_VERSION=4706cc3f31be576b66abeb6a9ef9f658830b525c

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
