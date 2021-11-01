#! /usr/bin/env bash
PY=$(python -c 'import site; print(site.getsitepackages()[0])')
ln -s /usr/lib/python3/dist-packages/broker $PY/broker
python -c 'import broker; print(broker.__file__)'
