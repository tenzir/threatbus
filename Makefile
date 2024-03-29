colon := :
$(colon) := :

.PHONY: all
all: format build dist test

.PHONY: install-dependencies
install-dependencies:
	python -m pip install -r requirements.txt

.PHONY: format
format:
	python -m black .

.PHONY: test
test: unit-tests integration-tests

.PHONY: unit-tests
unit-tests:
	python -m unittest discover threatbus
	$(MAKE) -C plugins/backbones/threatbus_inmem unit-tests
	$(MAKE) -C plugins/backbones/threatbus_rabbitmq unit-tests
	$(MAKE) -C plugins/apps/threatbus_zmq unit-tests
	$(MAKE) -C plugins/apps/threatbus_misp unit-tests
	$(MAKE) -C plugins/apps/threatbus_zeek unit-tests
	$(MAKE) -C plugins/apps/threatbus_cif3 unit-tests
	$(MAKE) -C apps/vast unit-tests
	$(MAKE) -C apps/stix-shifter unit-tests
	$(MAKE) -C apps/suricata unit-tests

.PHONY: integration-tests
integration-tests:
	-docker kill rabbit-int > /dev/null 2>&1
	docker pull rabbitmq$(:)3 > /dev/null 2>&1
	docker run -d --rm --hostname=test-rabbit --name=rabbit-int -p 35672$(:)5672 rabbitmq$(:)3 > /dev/null 2>&1
	-python -m unittest tests/integration/test_misp_inmem.py
	-python -m unittest tests/integration/test__management.py
	-python -m unittest tests/integration/test__message_roundtrips.py
	-python -m unittest tests/integration/test_zeek_app.py
	-python -m unittest tests/integration/test_zeek_inmem.py
	-python -m unittest tests/integration/test_rabbitmq.py
	-${RM} {broker,intel,reporter,weird}.log
	docker kill rabbit-int > /dev/null 2>&1

.PHONY: clean
clean:
	-${RM} -r __pycache__ *egg-info build dist
	-$(MAKE) -C plugins/apps/threatbus_zeek clean
	-$(MAKE) -C plugins/apps/threatbus_misp clean
	-$(MAKE) -C plugins/apps/threatbus_zmq clean
	-$(MAKE) -C plugins/apps/threatbus_cif3 clean
	-$(MAKE) -C plugins/backbones/threatbus_inmem clean
	-$(MAKE) -C plugins/backbones/threatbus_rabbitmq clean
	-$(MAKE) -C apps/vast clean
	-$(MAKE) -C apps/stix-shifter clean
	-$(MAKE) -C apps/suricata clean

.PHONY: build
build:
	python setup.py build
	$(MAKE) -C plugins/apps/threatbus_zeek build
	$(MAKE) -C plugins/apps/threatbus_misp build
	$(MAKE) -C plugins/apps/threatbus_zmq build
	$(MAKE) -C plugins/apps/threatbus_cif3 build
	$(MAKE) -C plugins/backbones/threatbus_inmem build
	$(MAKE) -C plugins/backbones/threatbus_rabbitmq build
	$(MAKE) -C apps/vast build
	$(MAKE) -C apps/stix-shifter build
	$(MAKE) -C apps/suricata build

.PHONY: dist
dist:
	python setup.py sdist bdist_wheel
	$(MAKE) -C plugins/apps/threatbus_zeek dist
	$(MAKE) -C plugins/apps/threatbus_misp dist
	$(MAKE) -C plugins/apps/threatbus_zmq dist
	$(MAKE) -C plugins/apps/threatbus_cif3 dist
	$(MAKE) -C plugins/backbones/threatbus_inmem dist
	$(MAKE) -C plugins/backbones/threatbus_rabbitmq dist
	$(MAKE) -C apps/vast dist
	$(MAKE) -C apps/stix-shifter dist
	$(MAKE) -C apps/suricata dist

.PHONY: install
install:
	pip install .
	$(MAKE) -C plugins/apps/threatbus_zeek install
	$(MAKE) -C plugins/apps/threatbus_misp install
	$(MAKE) -C plugins/apps/threatbus_zmq install
	$(MAKE) -C plugins/apps/threatbus_cif3 install
	$(MAKE) -C plugins/backbones/threatbus_inmem install
	$(MAKE) -C plugins/backbones/threatbus_rabbitmq install
	$(MAKE) -C apps/vast install
	$(MAKE) -C apps/stix-shifter install
	$(MAKE) -C apps/suricata install

.PHONY: dev-mode
dev-mode:
	pip install --editable .
	$(MAKE) -C plugins/apps/threatbus_zmq dev-mode
	$(MAKE) -C plugins/backbones/threatbus_inmem dev-mode
	$(MAKE) -C plugins/backbones/threatbus_rabbitmq dev-mode
	$(MAKE) -C plugins/apps/threatbus_misp dev-mode
	$(MAKE) -C plugins/apps/threatbus_zeek dev-mode
	$(MAKE) -C plugins/apps/threatbus_cif3 dev-mode
	$(MAKE) -C apps/vast dev-mode
	$(MAKE) -C apps/stix-shifter dev-mode
	$(MAKE) -C apps/suricata dev-mode
