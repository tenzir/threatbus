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
	python -m unittest discover plugins/apps
	python -m unittest discover plugins/backbones

.PHONY: integration-tests
integration-tests:
	docker build . -t threatbus-integration-test
	docker run -td --name=tb-int --rm -p 47761:47761 threatbus-integration-test -c config_integration_test.yaml
	-python -m unittest tests/integration/test_zeek_inmem.py
	-${RM} {broker,intel,reporter,weird}.log
	docker kill tb-int

.PHONY: clean
clean:
	-find . -type d -name "*egg-info" -exec ${RM} -r {} \;
	-find . -type d -name "__pycache__" -exec ${RM} -r {} \;
	-${RM} -r build

.PHONY: build
build:
	python setup.py build
	python plugins/apps/threatbus_zeek/setup.py build
	python plugins/apps/threatbus_misp/setup.py build
	python plugins/apps/threatbus_vast/setup.py build
	python plugins/apps/threatbus_cif3/setup.py build
	python plugins/backbones/threatbus_inmem/setup.py build
	python plugins/backbones/threatbus_rabbitmq/setup.py build

.PHONY: dist
dist:
	python setup.py sdist bdist_wheel
	make clean
	python plugins/apps/threatbus_zeek/setup.py sdist bdist_wheel
	make clean
	python plugins/apps/threatbus_misp/setup.py sdist bdist_wheel
	make clean
	python plugins/apps/threatbus_vast/setup.py sdist bdist_wheel
	make clean
	python plugins/apps/threatbus_cif3/setup.py sdist bdist_wheel
	make clean
	python plugins/backbones/threatbus_inmem/setup.py sdist bdist_wheel
	python plugins/backbones/threatbus_rabbitmq/setup.py sdist bdist_wheel
	make clean

.PHONY: install
install:
	python setup.py install
	python plugins/apps/threatbus_zeek/setup.py install
	python plugins/apps/threatbus_misp/setup.py install
	python plugins/apps/threatbus_vast/setup.py install
	python plugins/apps/threatbus_cif3/setup.py install
	python plugins/backbones/threatbus_inmem/setup.py install
	python plugins/backbones/threatbus_rabbitmq/setup.py install

.PHONY: dev-mode
dev-mode:
	python setup.py develop
	python plugins/apps/threatbus_zeek/setup.py develop
	python plugins/apps/threatbus_misp/setup.py develop
	python plugins/apps/threatbus_vast/setup.py develop
	python plugins/apps/threatbus_cif3/setup.py develop
	python plugins/backbones/threatbus_inmem/setup.py develop
	python plugins/backbones/threatbus_rabbitmq/setup.py develop
